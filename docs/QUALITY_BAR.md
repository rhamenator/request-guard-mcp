# Request Guard release quality bar

Status: acceptance criteria for the **inbound request classifier**. The optional egress prototype in this branch is being extracted into the independent [Outbound Guard MCP](https://github.com/rhamenator/outbound-guard-mcp) repository. Neither product requires the other at runtime.

## Classification and evidence

- Every verdict has stable rule IDs, bounded explanation, confidence or score meaning, policy version, and traceable evidence without exposing credentials or personal data. False-positive and false-negative tradeoffs are measured on documented fixtures, not inferred from a passing unit suite.
- Attested TLS fingerprints are accepted only from verified producers, scoped to the request, freshness-checked, and included in cache identity. Missing Redis, PostgreSQL, or MaxMind data yields explicit degraded behavior rather than fabricated enrichment.
- Canary, reputation, rate, and abuse-signal behavior is deterministic under concurrency and storage failure. Load tests cover backpressure, timeouts, cache invalidation, and resource bounds.

## MCP and integration

- Each advertised transport and tool is probed against the [MCP 2026-07-28 protocol](https://modelcontextprotocol.io/specification/2026-07-28) or an explicitly negotiated earlier revision. Current HTTP JSON-RPC POST and WebSocket support must be named accurately until full current Streamable HTTP conformance is verified.
- The `ai-scraping-defense` projects can opt to connect to this server, another MCP server, or none. Compatibility tests verify that choice without hidden coupling.
- Install guides give copyable examples for supported clients and deployments, required permissions, safe defaults, health checks, and expected first results.

## Operational finish

- CI, CodeQL, dependency review, adversarial fixtures, fuzz or property tests for parsers and schemas, reproducible release artifacts, checksums, changelog, GPL-3.0-or-later license, security reporting, and support guidance are required. A threat model maps each security claim to code and a test.
- Startup validates configuration, refuses unsafe authentication/bind combinations, and reports actionable errors. Metrics and audit logs are scoped, redacted, and bounded; operational alerts identify degraded backends and policy failures.
- A stable release requires the repository's human release-readiness review with known risks and exceptions recorded. Documentation must not call experimental egress behavior production-ready.
