# WebSocket size-limit close evidence — 2026-10-19

Issue #65 follows the baseline evidence in `adversarial-evidence-ws-size-2026-10-19.md`. The fix was tested on this PR branch based on main commit `f616583`, using a locally built debug server with SHA-256 `e2bc742fe1812022f3afe0880c757392b4c98701efceb4e2fc675691401ca538`. The probe used Python 3.14.4, a temporary loopback port, a synthetic bearer token, and a 4096-byte request cap. No VM or external target was used.

Command: `python3 scripts/ci_adversarial_smoke.py --binary <locally-built-request-guard-mcp>`. The wrapper passes the bearer token to the WebSocket probe over stdin and stops the server afterward.

| Case | Expected | Observed |
| --- | --- | --- |
| One masked 4097-byte text frame | Close frame, code 1009 | Close frame, code 1009 |
| Two smaller masked fragments totaling 4097 bytes | Close frame, code 1009 | Close frame, code 1009 |
| New authenticated connection after both rejects | `ping` succeeds | WebSocket text response with empty result |

The stricter probe passed 11/11 WebSocket cases. The same run passed HTTP 10/10, classifier 8/8, and slow-client 4/4. Python probe unit tests passed 2/2. This demonstrates bounded rejection and recovery, not sustained exhaustion resistance. The historical v0.1.1 release still hard-closes oversized WebSocket messages. The packaged-release adversarial gate remains open.

The local library suite passed 42/44 tests. Its two pre-existing slow-client
unit cases timed out in this host run, including when retried alone; the live
slow-client probe passed 4/4. CI must pass the full test suite before merge.
