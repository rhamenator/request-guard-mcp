# Architecture

## Overview

`request-guard-mcp` is a **Model Context Protocol (MCP) server** implemented in Rust. It provides request classification and enrichment over WebSocket, HTTP JSON-RPC, or process-local stdio. The `ai-scraping-defense` Python, IIS, and Rust projects are compatible clients, but they are not required dependencies.

```
┌──────────────────────────┐   WebSocket/MCP   ┌────────────────────────────────┐
│  Any MCP-capable client   │ ─────────────────► │  request-guard-mcp            │
│  or model adapter         │                   │  (Rust / Tokio / Axum)         │
└──────────────────────────┘                   │                                │
                                               │  ┌─────────────┐               │
┌──────────────────────────┐   WebSocket/MCP   │  │ Tool Registry│               │
│  Legacy ASD clients      │ ─────────────────► │  └──────┬──────┘               │
│  (Python / IIS / Rust)   │                   │         │                      │
└──────────────────────────┘                   │  ┌──────▼──────────────────┐   │
                                               │  │  Engines                │   │
                                               │  │  ├── RuleEngine         │   │
                                               │  │  ├── Scorer             │   │
                                               │  └─────────────────────────┘   │
                                               │                                │
                                               │  Integrations (optional)       │
                                               │  ├── Redis (cache/reputation)  │
                                               │  ├── PostgreSQL (decisions/FB) │
                                               │  └── MaxMind GeoIP (MMDB)      │
                                               └────────────────────────────────┘
```

## Request Lifecycle

1. A network client opens a WebSocket connection or sends an HTTP POST to `/mcp`; a local client can instead launch `request-guard-mcp --stdio` and exchange one JSON-RPC message per line.
2. The `/mcp` network endpoint checks Bearer tokens when authentication is enabled and then applies the configured Origin policy. Stdio uses a process-local caller scope and does not accept an HTTP Authorization header. Network `/health`, `/ready`, and the configured metrics route (default `/metrics`) are unauthenticated; restrict access at the listener or proxy.
3. Client sends a JSON-RPC 2.0 message, typically `initialize` followed by `tools/list` or `tools/call`.
4. Tool calls acquire a global semaphore permit; protocol methods `initialize`, `ping`, and `tools/list` do not.
5. Tool dispatch is bounded by the classify timeout or the general per-tool timeout. Optional Redis operation bookkeeping has separate bounds.
6. The rule engine extracts signals and the scorer produces the verdict.
7. Backend-dependent tools query Redis, PostgreSQL, or MaxMind as required.
8. The response is serialized over the selected transport and metrics/traces are emitted.

## Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| `main.rs` | `src/main.rs` | Entry point, startup |
| `config` | `src/config.rs` | Configuration loading (env + file) |
| `state` | `src/state.rs` | Shared application state, metrics |
| `auth` | `src/auth.rs` | Token validation |
| `limits` | `src/limits.rs` | Request/batch size enforcement |
| `telemetry` | `src/telemetry.rs` | Tracing + Prometheus metrics |
| `mcp/server` | `src/mcp/server.rs` | Axum router, startup |
| `mcp/transport_ws` | `src/mcp/transport_ws.rs` | WebSocket connection handler |
| `mcp/transport_stdio` | `src/mcp/transport_stdio.rs` | Process-local line-delimited JSON-RPC |
| `mcp/protocol` | `src/mcp/protocol.rs` | JSON-RPC 2.0 message types |
| `mcp/tool_registry` | `src/mcp/tool_registry.rs` | Tool registration + dispatch |
| `engines/rules` | `src/engines/rules.rs` | Pattern-based signal extraction |
| `engines/scorer` | `src/engines/scorer.rs` | Score aggregation + verdict |
| `engines/explain` | `src/engines/explain.rs` | Human-readable explanations |
| `engines/anomaly` | `src/engines/anomaly.rs` | Unwired statistical anomaly prototype; it does not affect tool results |
| `engines/policy` | `src/engines/policy.rs` | Unwired threshold prototype; active verdict thresholds are constants in `engines/scorer` |
| `tools/*` | `src/tools/` | All 23 MCP tool implementations |
| `integrations/*` | `src/integrations/` | Redis, PostgreSQL, MaxMind, reputation adapters |
| `util/*` | `src/util/` | Time, JSON, network, hashing helpers |

Network mode exposes MCP JSON-RPC over WebSocket and HTTP POST at `/mcp`;
`--stdio` is a separate process-local transport. gRPC is not an application
transport; the gRPC dependency visible in the build belongs to OTLP trace export.

## Concurrency Model

- **Async runtime**: Tokio with `rt-multi-thread`
- **Global tool concurrency**: `tokio::sync::Semaphore` with configurable limit (default 256)
- **Tool timeout**: wraps dispatch with `tokio::time::timeout`; `classify` has a separate timeout setting
- **Classification cache**: process-local Moka cache with fixed 10,000-entry capacity and 300-second TTL; optional Redis distributed cache is read first. Keys include caller scope and a build/TLS-policy domain.
- **Backpressure**: saturated tool calls return JSON-RPC error `-429` / `RATE_LIMIT_EXCEEDED` without waiting for a permit. HTTP carries this tool error in an HTTP 200 JSON-RPC response; load balancers must inspect the body to recognize it. Separate WebSocket connection limits can reject an upgrade with HTTP 503.

## Observability

- **Logging**: `tracing` + `tracing-subscriber` with JSON formatter
- **Metrics**: Prometheus counters/histograms exposed without Bearer authentication at the configured metrics path (default `/metrics`)
  - `mcp_requests_total{tool, status}`
  - `mcp_request_duration_seconds{tool}` (histogram buckets; quantiles require a PromQL calculation)
  - `mcp_active_connections` (WebSocket connections only)
  - `mcp_tool_errors_total{tool, error_code}`
- **Metric limits**: tool calls shed before permit acquisition are not included in these tool-request counters or histograms; timeouts count under `mcp_requests_total{status="timeout"}` but not `mcp_tool_errors_total`. Unknown tool names share one bounded metric label.
- **Health**: unauthenticated `GET /health` always returns HTTP 200 with component status; unauthenticated `GET /ready` returns HTTP 503 when configured backends or capacity are unavailable.
- **OTLP**: Optional batched OpenTelemetry trace export via `MCP__TELEMETRY__OTLP_ENDPOINT`
