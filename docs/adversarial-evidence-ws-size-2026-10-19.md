# WebSocket size-limit evidence — 2026-10-19

This bounded local run exercised the actual WebSocket listener of a debug
binary built from commit `13c0eebac128399a15f5e2c9daacc2dd00cf1206`
(SHA-256 `70b70e13c0d05b972c9f63e3efa7f0801463255b0de24f69aa86f4031d1b6fbe`).
The server's Rust source is unchanged in main commit
`07c3e2700c46597a9b914e98f3c6456eaad67f5d`. The probe ran with Python
3.14.4, a temporary loopback port, a synthetic bearer token, and a 4096-byte
WebSocket message/frame cap. No VM or external target was used.

Command: `python3 scripts/ci_adversarial_smoke.py --binary
<locally-built-request-guard-mcp>`. The wrapper passed the token to the
WebSocket probe over stdin and stopped the server after the run.

| Case | Expected | Observed |
| --- | --- | --- |
| One masked 4097-byte text frame | Connection rejected or closed without a tool response | TCP connection hard-closed |
| Two individually smaller masked fragments totaling 4097 bytes | Connection rejected or closed without a tool response | TCP connection hard-closed |
| New authenticated connection after both rejects | `ping` succeeds | WebSocket text response with an empty result object |

WebSocket cases passed 11/11, including the pre-existing handshake and
protocol cases. HTTP passed 10/10, classifier passed 8/8, and slow-client
cases passed 4/4 in the same run. Host I/O PSI full avg10 was 0.00% afterward;
load averages were 0.79, 0.94, 0.85. All VMs remained off. GitHub CI will
repeat the probe on a fresh build after merge.

The current server does not send a WebSocket close frame with code 1009 when
these size limits trigger; the connection simply closes. The probe records
that behavior and checks recovery, but does not establish graceful close
semantics. These are small boundary cases, not sustained memory or connection
exhaustion tests. The packaged-release adversarial gate remains open.
