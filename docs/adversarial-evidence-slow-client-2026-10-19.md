# Slow-client and body-limit evidence — 2026-10-19

This bounded local run exercised the actual HTTP listener of a debug binary
built from commit `13c0eebac128399a15f5e2c9daacc2dd00cf1206` (SHA-256
`70b70e13c0d05b972c9f63e3efa7f0801463255b0de24f69aa86f4031d1b6fbe`).
The server's Rust source is unchanged in main commit
`5f7a42d0fa5af02038411bdcbcb7944a378a3c77`. The probe ran with Python
3.14.4 using a temporary loopback port and synthetic bearer token. No VM or
external target was used.

Command: `python3 scripts/ci_adversarial_smoke.py --binary
<locally-built-request-guard-mcp>`. The wrapper configured a 4096-byte request
limit and one-second header/body timeouts, then stopped the server after the
probes. The token was passed to the probes over stdin and not printed.

| Case | Expected | Observed |
| --- | --- | --- |
| Incomplete headers | Connection closes or HTTP timeout response | Connection closed within five seconds |
| Authenticated body stalled after one byte | HTTP 408 | HTTP 408 |
| Complete chunked body of 4097 bytes | HTTP 413 | HTTP 413 |
| Authorized `ping` after those cases | JSON-RPC success over HTTP 200 | HTTP 200 with empty result object |

All four cases passed. In the same run, transport probes passed HTTP 10/10 and
WebSocket 8/8; classifier probes passed 8/8. Afterward, host I/O PSI full
avg10 was 0.01% and load averages were 1.65, 1.55, 1.27. All VMs remained
off. The CI job will rerun this subset against a fresh build on an independent
host after merge.

After review identified a standalone-probe edge case, the same binary was
started in a second local fixture with a 64-byte body limit and the same
one-second timeouts. `scripts/adversarial_slow_client_probe.py
--max-request-bytes 64` passed 4/4: the stalled body still received 408,
the 65-byte chunked body received 413, and the subsequent ping succeeded.

This is a small timeout and body-limit check, not sustained exhaustion or a
measurement of maximum memory use. It does not cover a packaged release,
backend failure/recovery, WebSocket oversized frames, or secret logging. The
adversarial release gate remains open.
