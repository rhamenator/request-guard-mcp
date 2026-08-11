# Compatibility Matrix

## MCP Client Configuration

Any MCP-capable client can connect to this server over WebSocket JSON-RPC. Clients that use `MODEL_URI` routing can use the following environment variables:

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
| MCP 1.0 | WebSocket (JSON-RPC 2.0) | ✅ |
| MCP 1.0 | HTTP (polling) | ❌ (planned) |
| MCP 1.0 | gRPC | ❌ (planned) |

## Tool Availability by Feature Flag

| Tool | Feature Flag | Default |
|------|-------------|---------|
| `classify` | always | enabled |
| `explain` | always | enabled |
| `batch_classify` | `enable_batch` | enabled |
| `feedback` | Persistence adapter required | disabled |
| `enrich_ip` | GeoIP/reputation adapter required | disabled |
| `enrich_asn` | ASN reputation adapter required | disabled |
| `enrich_ua` | `enable_enrichment` | enabled |
| `replay_decision`, `threat_lookup`, `canary_eval`, `drift_report`, `calibration_report`, `queue_status` | Backend adapter required | disabled |
| All other tools | always | enabled |

Disabled tool contracts remain registered for compatibility and return
`INTEGRATION_UNAVAILABLE`; they never return synthetic success data.

## Tested Client Versions

| Client | Version | Status |
|--------|---------|--------|
| `ai-scraping-defense` | main | ✅ Compatible |
| `ai-scraping-defense-iis` | main | ✅ Compatible |
| `ai-scraping-defense-rust` | main | ✅ Compatible |
