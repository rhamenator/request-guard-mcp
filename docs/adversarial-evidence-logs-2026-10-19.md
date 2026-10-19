# Synthetic-secret log evidence — 2026-10-19

This bounded run used the actual HTTP listener of a debug binary built from
main commit `c5b71a5`, SHA-256
`e2bc742fe1812022f3afe0880c757392b4c98701efceb4e2fc675691401ca538`.
The source changes between that commit and main `c9b9ba0` affected probes and
docs, not the server binary. Python 3.14.4 started an isolated loopback
server with debug-level JSON logs, a temporary synthetic bearer token, and
a synthetic request marker. No VM or external target was used. The host had
high I/O pressure before the run, so the already built binary was reused.

Command: `python3 scripts/ci_adversarial_smoke.py --binary
<locally-built-request-guard-mcp>`. The log probe sent one wrong bearer
credential (HTTP 403) and one authenticated standard MCP `tools/call` for
`classify` (HTTP 200), placing the marker in `user_agent` and `path`. It
captured at most 1 MiB of process output in an unnamed temporary file and
confirmed the startup and rejected-auth log events were present. Neither
the synthetic token nor marker appeared in the captured logs. The probe
passed 3/3. The wrapper also passed HTTP 10/10, WebSocket 11/11,
classifier 8/8, optional-backend 2/2, slow-client 4/4, and connection-cap
3/3. The log file was discarded after the run; no token or marker was
printed or committed.

This demonstrates no direct plaintext leakage in this bounded local path.
It does not inspect reverse-proxy, OTLP, Redis, PostgreSQL, shell history,
crash dumps, transformed encodings, or every tool input. The packaged-release
adversarial gate remains open.
