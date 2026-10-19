# JSON-RPC transport smoke evidence — 2026-10-19

This bounded run exercised a locally built server from main commit
`13c0eebac128399a15f5e2c9daacc2dd00cf1206` through its actual HTTP and
WebSocket listeners. The binary was a debug build made with `cargo build
--locked --bin request-guard-mcp`; SHA-256:
`70b70e13c0d05b972c9f63e3efa7f0801463255b0de24f69aa86f4031d1b6fbe`.
Python 3.14.4 and rustc 1.96.0 were used.

Command: `python3 scripts/ci_adversarial_smoke.py --binary
<locally-built-request-guard-mcp>`. The wrapper bound only to loopback on a
temporary port, generated a synthetic bearer token, set no optional backend,
ran the stdlib HTTP and WebSocket probes, and stopped the server. The token
was not printed or committed. No VM or external target was used.

Expected and observed: HTTP 10/10 passed, covering missing and wrong tokens,
authorized RPC, malformed JSON `-32700`, invalid version/ID/params `-32600`,
invalid tool input, injection text handled as request data, and a declared
oversized body rejected with 413. WebSocket 8/8 passed, covering authentication,
upgrade, initialize, malformed JSON, invalid version and params, and tool
discovery. The wrapper printed the binary digest and each case outcome. Host
I/O PSI full avg10 was 0.00% after the run; load averages were 2.44, 1.54,
0.96. All VMs remained off.

The smoke is now scheduled on GitHub CI against each freshly built source
binary. It does not establish packaged-release equivalence or cover sustained
exhaustion, backend failure/recovery, classifier evasion, secret logging, or
complete MCP client interoperability. The adversarial release gate remains
open; v0.1.1 is still experimental.
