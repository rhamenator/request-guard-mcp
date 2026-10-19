# Expanded Kali-to-Ubuntu candidate run — 2026-10-19

This bounded run exercised a release-profile build of `origin/main` at
`5800eccb127c0644357a91ded3749623106a03b2` from Kali against Request
Guard inside Ubuntu. It extended the earlier 35-case guest-server regression
with a real Redis outage, caller cache separation, a bounded malformed-envelope
probe, and connection shedding. The tested binary SHA-256 was
`0f5b890f4922ad863c9c270979dde779751aa6477baa23c7df3ffee4ec5c95ae`.
The build used `cargo build --release --locked` with rustc 1.96.0. The binary
still self-identifies as 0.1.1; this is **not** a packaged next release.

## Lab and limits

- Server: `copperfin-ubuntu26-deb`, `192.168.122.73`; client:
  `copperfin-kali-full`, `192.168.122.74`. Both guests ran concurrently.
  Kali used Python 3.14.7, Nmap 7.99, and Nikto 2.6.1. The host used Node
  22.20.0 and official MCP Inspector 2.5.0 for an additional client check.
- The server had a fresh synthetic 64-character bearer token, a 4096-byte
  request cap, and one-second HTTP header/body timeouts on port 18086. The
  two-slot connection-cap listener used port 18087 and a ten-second header
  timeout. Separate listeners on 18088 and 18090 accepted two synthetic
  tokens. Redis-backed listeners used port 18089 or 18090.
- Redis 8.0.5 was downloaded and extracted under Ubuntu `/tmp`, with the
  missing `liblzf1` library extracted there too. It ran only on
  `127.0.0.1:16379`, without persistence. No Redis package or service was
  installed in the guest.
- Host full I/O PSI was `avg10=0.00 avg60=0.28` before VM boot and
  `avg10=0.00 avg60=0.02` after shutdown. During the bounded probes it was
  observed at `avg10=0.08 avg60=0.06` and later at 0.00/0.00. No firewall
  changes were needed. Both guests shut down cleanly; all synthetic token
  files were removed from host and guests.

## Kali-to-Ubuntu observations

| Check | Result |
| --- | --- |
| `adversarial_probe.py --url http://192.168.122.73:18086 --max-request-bytes 4096` | 10/10 HTTP/auth/JSON-RPC/input cases passed. |
| `adversarial_ws_probe.py --host 192.168.122.73 --port 18086 --max-request-bytes 4096` | 11/11 WebSocket cases passed, including close code 1009 and recovery. |
| `adversarial_classifier_probe.py --url http://192.168.122.73:18086` | 10/10 benign, bot, and encoded-path cases passed. |
| `adversarial_slow_client_probe.py --host 192.168.122.73 --port 18086 --max-request-bytes 4096` | 4/4 slow-header, slow-body, chunked-limit, and recovery cases passed. |
| `adversarial_backend_probe.py --url http://192.168.122.73:18086` | 2/2 unavailable optional Redis and healthy core cases passed. |
| `adversarial_connection_cap_probe.py --host 192.168.122.73 --port 18087` | 3/3 two-slot shedding and recovery cases passed. |
| Deterministic malformed-envelope probe, seed `0xA11CE`, 128 requests against 18087 | 128/128 received a structured error and a subsequent authenticated ping succeeded. One first-run test expectation omitted the server's `-404` unknown-method response; the corrected expectation passed. |
| Bounded connection burst against the two-slot listener | 128/128 excess connections were shed, none errored, maximum observed close latency 1.36 ms, and authenticated ping recovered. |
| Two-token listener on 18088 | Both configured tokens received HTTP 200 for `ping`; an unlisted token received 403 (3/3). |
| Synthetic log probe | A rejected token returned 403 and `classify` returned 200. The bounded 839-byte debug capture contained the rejection event but neither the token nor synthetic request marker. |
| Live Redis outage on 18089 | Before outage: `threat_lookup` succeeded (`found=false`). During outage: structured `-502 UPSTREAM_ERROR`; `classify` still succeeded. After Redis restart: `threat_lookup` succeeded again. Each phase completed in under 30 ms. |
| Redis cache separation on 18090 | For a fresh identical request, cache-key count went 3 → 4 after token one, remained 4 on its repeat, then rose to 5 after token two. Distinct keys did not contain raw tokens. |

The four original scripts above came from commit `5800ecc` and had SHA-256
values `f386de994c554d8e66a9cf8d8081cda328a24c1db0d7ec208d1c3c30b31cc2f5`,
`6b1f50ccca9af4fbb028fd7bd1c405218428380d8132d4ae9545320f762cfa59`,
`57f95ff2d9ac5fb85591c35db8cc69f63bbcaf152bcea7b2d21ec70460fc6df2`,
and `85aacb03b31934275391420919cd186bbe007ca7b18db2d14f1bfc2b24e5a683`.
The temporary cross-VM fuzz and connection-burst scripts had SHA-256 values
`757ddc3fc4f99a439582eaa97ba29c2a21f42a12f6592ccf6ff087dc4c9cb774`
and `338709d78e3323e6c017f67aa6839dae76b60a6bd1ae29313f2472cd1fd2f9d4`.
The committed versions in this PR use stdin for synthetic tokens, accept
explicit target options, and passed the local CI smoke against the same binary.

## Client and scanner checks

Official MCP Inspector 2.5.0 was installed from a cached npm package on the
host and connected to Ubuntu port 18087. `initialize`, `tools/list` (23 tools),
`tools/call classify`, and `tools/call explain` passed. This is an actual MCP
client check but was host-to-Ubuntu, not Kali-to-Ubuntu.

From Kali, Nmap 7.99 ran
`nmap -Pn -sT -sV -p 18087 --script http-methods,http-headers --max-retries 1 --host-timeout 60s 192.168.122.73`.
The single target port was open; malformed service probes received HTTP 400
and unknown paths 404. No version banner was identified. Nikto 2.6.1 ran
`nikto -host http://192.168.122.73:18087 -maxtime 15s -timeout 2 -nointeractive -Tuning 1234 -Pause 0.05`.
It stopped at the 15-second cap with zero transport errors and four generic
browser/TLS header suggestions. Nikto did not report an exact request count,
so this scan is supplemental and does not satisfy the gate's request-count
recording rule. The suggestions are not confirmed defects for this API behind
a TLS proxy.

## Reproduction and remaining gate

Run `python3 scripts/ci_adversarial_smoke.py --binary PATH` to reproduce the
same code-level HTTP, WebSocket, classifier, backend-unavailable, slow-client,
log, connection-cap, 128-case envelope, and 128-attempt connection probes on
loopback. This passed against the binary hash above. The live Redis cycle,
cache separation, official Inspector, and scanners were manual, bounded lab
checks; their exact conditions and results are recorded here. The synthetic
credentials were never committed.

The full gate remains open for a PostgreSQL outage and recovery, longer but
resource-bounded exhaustion under monitored host load, scanner request counts,
additional independent classifier-evasion cases, and review of the exact
packaged next-release artifacts on both VMs and with actual MCP clients.
Independent Claude Code and Codex reviews must be reconciled. Do not promote
v0.1.1 or upload a skill ZIP as representing these fixes. The Alpine host work
is tracked separately in issue #54 for the release after this one.
