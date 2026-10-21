# Compatibility Matrix

## MCP Client Configuration

Compatible clients connect to `/mcp` with authenticated HTTP POST JSON-RPC;
custom WebSocket clients can use the same path. The server implements
`initialize`, `ping`, `tools/list`, and `tools/call` while retaining direct
tool methods. The handshake revision is `2025-06-18`; if a client offers a
different revision, `initialize` counter-offers that version and the client
must decide whether it can continue. v0.1.5 adds process-local stdio but does
not implement the `2026-07-28` discovery lifecycle, OAuth discovery, SSE GET,
resources, or prompts. MCP Inspector 2.5.0 smoke passed in the
[five-platform v0.1.4 release evidence](releases/v0.1.4-postgres-tls-evidence.md),
including the packaged Alpine binary; see also the
[interoperability evidence](inspector-interoperability.md). The supported HTTP
and custom WebSocket envelope cases were also exercised against the exact
public v0.1.4 binary; optional transports and broader client coverage are
tracked in issue #121.

The official Python MCP SDK 2.3.0 also completed authenticated Streamable
HTTP `initialize`, `tools/list`, and `classify` against the public Linux x64
v0.1.4 binary (SHA256 `e1863970dc8fdc96bb861af667bf7bc3f52810b2319190f8f2c192b033ab0fd5`).
The reproducible [client probe](../scripts/python_sdk_smoke.py) uses a local
listener and synthetic bearer token. The SDK tolerates the server's 405 for
SSE GET. This verifies that specific SDK path; it does not add SSE GET, stdio,
or session support. To repeat it in a disposable Python virtual environment:

```sh
pip install 'mcp==2.3.0'
python scripts/python_sdk_smoke.py --binary /path/to/request-guard-mcp --expected-version 0.1.4
```

The probe also checks that a request without the bearer token receives HTTP 401.

For v0.1.4 and later HTTP POST, send `Content-Type: application/json` and
`Accept: application/json, text/event-stream`. The server returns JSON for
requests and rejects an explicit unsupported content type with 415 or an
explicit `Accept` excluding JSON with 406. After initialization, send
`MCP-Protocol-Version: 2025-06-18`; an explicit invalid, duplicate, or
unsupported version gets 400 before the body is read. Missing headers remain
accepted for older direct clients, without implying support for older
protocol revisions. The custom WebSocket upgrade does not use the HTTP
version header.

Use JSON-RPC `2.0` with a string or integer request ID. v0.1.4 rejects
`null`, fractional, or other invalid request IDs with `-32600` and an error
ID of `null`. It rejects fractional client-response IDs and a `null` success-
response ID; `null` remains valid for a parse or invalid-request error when
the original ID cannot be recovered. Client success-response `result` and
request/notification `params`, when present, must be JSON objects. A valid
request ID is echoed for invalid `params`. Rejected ID-less HTTP
notifications or client responses get 400 with no body; accepted ones get 202
with no body. The custom WebSocket transport reports malformed messages as
JSON-RPC errors.

The earlier v0.1.3 release predates these v0.1.4 HTTP/envelope checks. Use
its [tagged documentation](https://github.com/rhamenator/request-guard-mcp/tree/v0.1.3)
when operating that version.

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
| 2025-06-18 | WebSocket JSON-RPC (custom client transport) | Implemented; 22-case packaged-binary envelope probe passed; broader client matrix open |
| 2025-06-18 | HTTP POST JSON-RPC | Inspector 2.5.0, Python MCP SDK 2.3.0, and 13-case packaged-binary envelope probe passed |
| 2025-06-18 | stdio | v0.1.5 native; official Python SDK 2.3.0, private packaged smoke on five platforms, and clean npm launcher smoke on Linux passed. One Claude Code 2.1.301 `classify` call against the exact public Linux x64 binary also succeeded; its negotiated protocol revision was not captured. Absent from v0.1.4. |
| 2025-06-18 | SSE GET, gRPC | Not implemented; v0.1.4 returns 405 for authenticated, ordinary GET `/mcp` |

v0.1.5 adds process-local `--stdio`, which trusts the launching user instead
of a bearer token. It does not add SSE GET support. See the
[native setup](../INSTALL.md) and [private pre-release evidence](releases/v0.1.5-stdio-candidate.md).
The bounded public-binary Claude Code client result and its limits are in
[v0.1.5 Claude Code stdio evidence](releases/v0.1.5-claude-code-stdio.md).

The [pinned MCP transport revision](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#sending-messages-to-the-server)
requires 202 with no body for accepted client notifications and responses;
v0.1.4 does so. JSON response mode and an authenticated GET 405 are permitted
by this pinned specification. Optional SSE and additional client transports
are tracked in issue #121.
Browser-originated HTTP POST and WebSocket MCP requests require an exact
`MCP_ALLOWED_ORIGINS` entry in addition to bearer authentication. The default
empty allowlist denies requests carrying `Origin`; clients without `Origin`
remain subject to the configured authentication policy. This follows the
[MCP DNS-rebinding guidance](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#security-warning).
Origin is spoofable outside a browser. The check covers MCP POST and WebSocket
upgrades, not health, readiness, or metrics. Cross-origin browser clients need
a trusted proxy for CORS preflight and response handling. Browser WebSocket
clients need that proxy to authenticate and supply the upstream bearer header.
Published v0.1.3 lacks the server-side Origin check; its proxy must enforce
that boundary.

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
