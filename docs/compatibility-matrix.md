# Compatibility Matrix

## MCP Client Configuration

Clients with compatible HTTP POST JSON-RPC behavior can connect to `/mcp`.
Custom WebSocket clients can also use that path with bearer authentication.
The server implements the standard `initialize`, `ping`,
`tools/list`, and `tools/call` methods while retaining direct tool-method
compatibility. Clients that use `MODEL_URI` routing can use the following
environment variables:

The current handshake revision is `2025-06-18`. If a client offers another
revision, `initialize` counter-offers `2025-06-18`; the client must decide
whether it supports that revision. The server does not yet implement the
`2026-07-28` discovery lifecycle. It does not expose stdio, OAuth discovery,
SSE GET streams, resources, or prompts. HTTP support has been smoke tested with
MCP Inspector 2.5.0, but full transport and client conformance remain part of
the adversarial release gate. See [the client evidence](inspector-interoperability.md).

### `rhamenator/ai-scraping-defense` (Python/Django)

```dotenv
MODEL_URI=mcp://primary/classify
MCP_SERVER_PRIMARY_TRANSPORT=ws
MCP_SERVER_PRIMARY_URL=ws://request-guard-mcp:8085/mcp
MCP_SERVER_PRIMARY_AUTH_TOKEN=replace_me
MCP_SERVER_PRIMARY_TIMEOUT=10
```

### `rhamenator/ai-scraping-defense-iis` (.NET/IIS)

```dotenv
MODEL_URI=mcp://primary/classify
MCP_SERVER_PRIMARY_TRANSPORT=ws
MCP_SERVER_PRIMARY_URL=ws://request-guard-mcp:8085/mcp
MCP_SERVER_PRIMARY_AUTH_TOKEN=replace_me
MCP_SERVER_PRIMARY_TIMEOUT=10
```

### `rhamenator/ai-scraping-defense-rust` (Rust services)

```dotenv
MODEL_URI=mcp://primary/classify
MCP_SERVER_PRIMARY_TRANSPORT=ws
MCP_SERVER_PRIMARY_URL=ws://request-guard-mcp:8085/mcp
MCP_SERVER_PRIMARY_AUTH_TOKEN=replace_me
MCP_SERVER_PRIMARY_TIMEOUT=10
```

> For TLS-terminated deployments replace `ws://` with `wss://` and the appropriate hostname.

The old `ai-scraping-defense-mcp` hostname is retained as a Docker/Kubernetes compatibility alias in the provided manifests.

## Fallback Strategy

If the MCP server is unavailable, clients should fall back to their local non-MCP classifiers:

| Client | Fallback |
|--------|---------|
| `ai-scraping-defense` | Built-in Python rule engine (`defense/classifier.py`) |
| `ai-scraping-defense-iis` | Built-in .NET rule engine (`AiDefense.Classifier`) |
| `ai-scraping-defense-rust` | Local Rust provider/router behavior |

Fallback is triggered when:
- WebSocket connection fails after 3 retries with exponential backoff
- MCP server returns `TIMEOUT` or `INTERNAL_ERROR` for 5 consecutive requests

## Transport Protocol

| Version | Transport | Supported |
|---------|-----------|-----------|
| 2025-06-18 | WebSocket JSON-RPC (custom client transport) | Implemented; client interoperability gate open |
| 2025-06-18 | HTTP POST JSON-RPC | Inspector 2.5.0 smoke passed; full conformance gate open |
| 2025-06-18 | stdio, SSE GET, gRPC | Not implemented |

Accepted HTTP POST notifications and client responses have no response body.
Development main returns HTTP 202; the published v0.1.3 server returns 204.
The [pinned MCP transport revision](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#sending-messages-to-the-server)
specifies 202 for accepted notifications and responses. Full Streamable HTTP
conformance remains open in issue #59.
On development main, browser-originated HTTP POST and WebSocket MCP requests
require an exact configured `MCP_ALLOWED_ORIGINS` entry. The default empty
allowlist denies requests carrying `Origin`, while non-browser requests without
it still use the configured authentication policy. This follows the
[MCP transport DNS-rebinding guidance](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#security-warning).
Published v0.1.3 has no server-side Origin check, so its reverse proxy must
enforce the intended browser-origin boundary. Origin is a browser protection,
not a replacement for a token: non-browser callers can forge that header.
The development check covers MCP POST and WebSocket upgrades. Health,
readiness, and metrics endpoints remain outside it. Cross-origin browser
clients need CORS preflight and response handling at a trusted proxy; the
allowlist does not add CORS to the server.

## Tool Availability by Feature Flag

| Tool | Feature Flag | Default |
|------|-------------|---------|
| `classify` | always | enabled |
| `explain` | always | enabled |
| `batch_classify` | `enable_batch` | enabled |
| `feedback` | PostgreSQL + `enable_feedback` | enabled when configured |
| `enrich_ip` | MaxMind or Redis reputation + `enable_enrichment` | enabled when configured |
| `enrich_asn` | MaxMind ASN or Redis reputation + `enable_enrichment` | enabled when configured |
| `enrich_ua` | `enable_enrichment` | enabled |
| `replay_decision`, `drift_report`, `calibration_report` | PostgreSQL | enabled when configured |
| `threat_lookup`, `canary_eval`, `queue_status` | Redis | enabled when configured |
| All other tools | always | enabled |

Backend-dependent contracts remain registered for compatibility. They return
`INTEGRATION_UNAVAILABLE` when their required backend is intentionally absent,
and `UPSTREAM_ERROR` when a configured backend fails at runtime; they never
return synthetic success data.

## Tested Client Versions

| Client | Version | Status |
|--------|---------|--------|
| `ai-scraping-defense` | main | ✅ Compatible |
| `ai-scraping-defense-iis` | main | ✅ Compatible |
| `ai-scraping-defense-rust` | main | ✅ Compatible |
