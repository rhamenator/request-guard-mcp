# v0.1.1 two-VM adversarial run — 2026-10-19

This bounded run exercised the **published Linux x64 v0.1.1 artifact** from the
Kali and Ubuntu lab VMs. It did **not** clear the stable-release adversarial
gate. The run ended before resource-exhaustion and backend-failure testing
because host I/O pressure rose substantially while both VMs were active.

## Scope and artifact

- Archive: `request-guard-mcp-v0.1.1-linux-x64.tar.gz`, downloaded from the
  official GitHub release; the release `.sha256` sidecar verified successfully.
- Extracted binary SHA-256:
  `06b8c844f8aec6c4a17081ee5eee24dc39dfae2e35b249d91efb8996fc19667c`.
- Server: host `192.168.122.1:18086`, bearer authentication with a fresh
  synthetic 64-character token; default request and connection limits; no
  Redis, PostgreSQL, MaxMind, or telemetry collector.
- Clients: `copperfin-kali-full` (`192.168.122.74`, Nmap 7.99, Nikto 2.6.1,
  Python 3.14) and `copperfin-ubuntu26-deb` (`192.168.122.73`, Python 3.14).
  Both VMs were running concurrently. Temporary UFW rules limited TCP 18086
  access to these two VM addresses on `virbr0`.
- The two probe scripts copied to each VM came from source commit
  `86ee83bc24f60fe42f4e3ca2605ceb1c9f89930d`, not the later CI probe
  revision. `scripts/adversarial_probe.py` had SHA-256
  `d3f8407cf2156abd87e0fe1838656f27ccd11bb9149fc6077bf06e02b0cd5236`;
  `scripts/adversarial_ws_probe.py` had SHA-256
  `e02f1c0cb6932d00a2779cc9fc096b2ca88437353ba7322c8e0a107a4e7aad3f`.
  These revisions implement the 7-case HTTP and 6-case WebSocket subsets
  reported below.

## Commands and observations

| Test | Result |
| --- | --- |
| `python3 /tmp/adversarial_probe.py --url http://192.168.122.1:18086 --token <synthetic-token>` from each VM | **7/7 passed on each**: missing and wrong auth, authorized RPC, malformed JSON, invalid parameter type, injection text as data, declared oversized body (413). The probe does not stream a large body. |
| Synthetic token on stdin to `python3 /tmp/adversarial_ws_probe.py --host 192.168.122.1 --port 18086` from each VM | **6/6 passed on each**: missing and wrong auth, authorized upgrade, initialize, malformed JSON, and `tools/list` with 23 tools. |
| `nmap -Pn -sT -sV -p 18086 --script http-methods,http-headers --max-retries 1 --host-timeout 60s 192.168.122.1` from Kali | Port open; malformed service probes received HTTP 400, unknown paths HTTP 404. No server version banner recognized. |
| `nikto -host http://192.168.122.1:18086 -maxtime 15s -timeout 2 -nointeractive -Tuning 1234` from Kali | 4,347 requests in about 3 seconds, zero transport errors, five generic browser/TLS header suggestions. These are not actionable without considering the intended TLS proxy and API-only deployment. |

No new product defect was confirmed in this bounded run. The tests above are
smoke and scanner checks, not a rigorous penetration-test pass.

## Resource observation and cleanup

Before VM startup, host load was 1.30, 32 GiB memory was available, and full
I/O PSI avg10 was 0.01%. After both VMs and the bounded Nikto run, full I/O
PSI avg10 rose to 22.77% and was still rising. The test stopped; full avg10
briefly reached 33.88% during VM shutdown. Concurrent backup/sync activity
means the VMs and scanner cannot be assigned sole causation. Both VMs shut
down cleanly, the lab server stopped, and both temporary UFW rules were
removed. The synthetic token stayed in a local owner-only temporary file and
was not committed.

## Remaining gate

Retest the exact candidate after host pressure is low enough to keep both VMs
responsive. Exercise slow headers and bodies, actual streamed body limits,
oversized WebSocket frames, bounded concurrency and sustained load, backend
failure and recovery (including Redis/PostgreSQL), sensitive-log redaction,
multi-token caller isolation, classifier evasion, and MCP client behavior.
Record resource measurements and regression results for any confirmed defect.
The full gate in `docs/adversarial-release-gate.md` remains open.
