# Classifier evasion smoke evidence — 2026-10-19

This bounded local run exercised `tools/call` with the `classify` tool over the
running server's HTTP listener. The server binary was built from commit
`13c0eebac128399a15f5e2c9daacc2dd00cf1206` (debug binary SHA-256
`70b70e13c0d05b972c9f63e3efa7f0801463255b0de24f69aa86f4031d1b6fbe`).
The classifier Rust source is unchanged in main commit
`fffa2f2df461cd4d8782e0ef08458ff29239eac5`. The probe script was run
from this branch with Python 3.14.4. It will also run on each CI build after
merge.

Command: `python3 scripts/ci_adversarial_smoke.py --binary
<locally-built-request-guard-mcp>`. The wrapper used a temporary loopback
port and synthetic bearer token, with no Redis, PostgreSQL, or MaxMind backend.
It printed no token and stopped the server. No VM or external target was used.

All eight expected signal checks passed through the live MCP tool interface:

| Input variation | Expected and observed |
| --- | --- |
| Ordinary browser on `/welcome` | No `ua_ai_bot` or `path_sensitive` signal |
| Mixed-case `gPtBoT/1.0` | `ua_ai_bot` signal |
| Browser-shaped UA containing `GPTBot/1.0` | `ua_ai_bot` signal |
| `/.env`, `/%2eenv`, `/%252eenv` | `path_sensitive` signal in each case |
| `/%2fadmin`, `/%255cadmin` | `path_sensitive` signal in each case |

The same run also passed the existing HTTP 10/10 and WebSocket 8/8 transport
probes. Host I/O PSI full avg10 was 0.00% after the run; load averages were
1.14, 1.22, 0.89. All VMs remained off.

These cases show that documented encodings and named-bot strings produce the
expected signals. A client can omit or forge its user-agent, and an origin may
decode URLs differently; this is not proof of bot identity or protection
against every evasion. It is not packaged-release or full adversarial-gate
evidence. Sustained exhaustion, backend failure/recovery, secret logging, and
broader evasion testing remain open.
