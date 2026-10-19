# Connection-cap evidence — 2026-10-19

This bounded run exercised the actual HTTP listener of the debug binary built
from main commit `c5b71a5`, SHA-256
`e2bc742fe1812022f3afe0880c757392b4c98701efceb4e2fc675691401ca538`.
The stdlib wrapper used a temporary loopback port, synthetic bearer token,
`MCP__LIMITS__MAX_CONNECTIONS=2`, and a ten-second HTTP header deadline.
No VM or external target was used. Host I/O PSI full avg10 was 0.34% after
this small run; all VMs remained off.

Command: `python3 scripts/ci_adversarial_smoke.py --binary
<locally-built-request-guard-mcp>`. The cap probe opened two partial-header
sockets, observed that a third socket was closed promptly, released both
held sockets, then received a successful authenticated `ping` on a new
connection. It passed 2/2. The same wrapper passed HTTP 10/10, WebSocket
11/11, classifier 8/8, and slow-client 4/4. The wrapper stops both server
processes after its probes.

This shows fail-fast shedding and immediate recovery for a two-slot lab
configuration. It does not test sustained connection floods, kernel backlog
behavior, distributed clients, or reverse-proxy limits. The packaged-release
adversarial gate remains open.
