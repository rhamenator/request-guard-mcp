# Kali-to-Ubuntu guest-server regression — 2026-10-19

This bounded run placed Request Guard inside the Ubuntu VM and sent real TCP
requests from the Kali VM. It compared the published experimental v0.1.1 Linux
x64 binary with a build of `origin/main` at `5800eccb127c0644357a91ded3749623106a03b2`.
It does not clear the full adversarial release gate.

## Reproduction

- Server: `copperfin-ubuntu26-deb`, `192.168.122.73:18086`. Client:
  `copperfin-kali-full`, `192.168.122.74`. Both guests ran simultaneously.
- Auth: fresh synthetic 64-character bearer token, supplied through a private
  temporary file and stdin; no real credential was used or recorded.
- Configuration: `MCP__HOST=192.168.122.73`, `MCP__PORT=18086`,
  `MCP__LIMITS__MAX_REQUEST_BYTES=4096`,
  `MCP__LIMITS__HTTP_HEADER_TIMEOUT_SECS=1`, and
  `MCP__LIMITS__HTTP_BODY_TIMEOUT_SECS=1`. No optional backends were enabled.
- Published archive SHA-256:
  `1cd4eb75ca857dc568f6b5dab01455e5885efd9abdcc85e050ee7f279f696427`;
  its official `.sha256` sidecar matched. Extracted release binary SHA-256:
  `06b8c844f8aec6c4a17081ee5eee24dc39dfae2e35b249d91efb8996fc19667c`.
- Current-main binary was built with `cargo build --release --locked` and had
  SHA-256 `0f5b890f4922ad863c9c270979dde779751aa6477baa23c7df3ffee4ec5c95ae`.
  Both binary hashes matched after copying into Ubuntu.
- Kali ran `scripts/adversarial_probe.py`, `adversarial_ws_probe.py`,
  `adversarial_classifier_probe.py`, and `adversarial_slow_client_probe.py`
  against each binary. Their SHA-256 values respectively were
  `f386de994c554d8e66a9cf8d8081cda328a24c1db0d7ec208d1c3c30b31cc2f5`,
  `6b1f50ccca9af4fbb028fd7bd1c405218428380d8132d4ae9545320f762cfa59`,
  `57f95ff2d9ac5fb85591c35db8cc69f63bbcaf152bcea7b2d21ec70460fc6df2`, and
  `85aacb03b31934275391420919cd186bbe007ca7b18db2d14f1bfc2b24e5a683`.

## Results

| Kali probe | Published v0.1.1 | Current main | Release failures |
| --- | ---: | ---: | --- |
| HTTP auth, MCP/JSON-RPC, body limit, instruction as data | 7/10 | 10/10 | Wrong JSON-RPC version, invalid request ID, scalar params |
| WebSocket auth, MCP/JSON-RPC, message size and recovery | 7/11 | 11/11 | Wrong JSON-RPC version, scalar params, two oversized messages closed without code 1009 |
| Classifier evasion signals | 8/10 | 10/10 | Triple and quadruple encoded `.env` path |
| Slow headers/body, chunked limit and recovery | 4/4 | 4/4 | None |

Every observed release failure was fixed in commits already on main: JSON-RPC
envelope validation (#60), WebSocket close code (#66), and repeated percent
encoding detection (#72). The release artifact remains unchanged and should
not be promoted as though those fixes were in v0.1.1.

Host full I/O PSI was `avg10=0.00 avg60=0.28` before Kali startup, remained
below the agreed 1% gate during these bounded probes, and was
`avg10=0.00 avg60=0.05` after the main build. No firewall change was needed;
Ubuntu UFW was inactive. The test used only the two named local guests.
Both guests shut down cleanly after the run, and the synthetic token was
removed from the host and both guests.

## Limits

This is a reproducible network regression test, not a comprehensive pentest.
It does not cover TLS termination, Redis/PostgreSQL failure, multi-token
isolation, sustained resource exhaustion, fuzzing, all MCP clients, or every
classifier bypass. The full gate in `docs/adversarial-release-gate.md` stays
open. A future release candidate must be tested as its exact packaged binary.
