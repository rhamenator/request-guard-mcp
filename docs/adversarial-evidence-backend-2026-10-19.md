# Optional-backend failure evidence — 2026-10-19

This bounded local run used the actual MCP HTTP listener of a debug binary
built from main commit `c5b71a5`, SHA-256
`e2bc742fe1812022f3afe0880c757392b4c98701efceb4e2fc675691401ca538`.
The wrapper used a temporary loopback port, a synthetic bearer token, and
an unconfigured Redis backend. No VM or external target was used. The host
had high I/O pressure before the run, so the existing binary was reused.

Command: `python3 scripts/ci_adversarial_smoke.py --binary
<locally-built-request-guard-mcp>`. An authenticated standard MCP
`tools/call` for `threat_lookup` returned HTTP 200 with JSON-RPC error
`-502`, message `INTEGRATION_UNAVAILABLE`, and the original request ID.
A subsequent authenticated `tools/call` for `classify` succeeded on the
same server with `isError:false` and structured content. The backend probe
passed 2/2; the same wrapper passed HTTP 10/10, WebSocket 11/11, classifier
8/8, slow-client 4/4, and connection-cap 3/3.

This verifies graceful behavior when optional Redis is absent. It does not
exercise a Redis outage during an active session, reconnection, PostgreSQL
failure, or sensitive-field logging. The packaged-release adversarial gate
remains open.
