# Architecture

## Overview

`ai-scraping-defense-mcp` is a production-ready **Model Context Protocol (MCP) server** implemented in Rust. It provides a unified, high-performance classification and enrichment API consumed by both `ai-scraping-defense` (Python/Django) and `ai-scraping-defense-iis` (.NET) via WebSocket transport.

```
┌──────────────────────────┐   WebSocket/MCP   ┌────────────────────────────────┐
│  ai-scraping-defense     │ ─────────────────► │  ai-scraping-defense-mcp       │
│  (Python / Django)       │                   │  (Rust / Tokio / Axum)         │
└──────────────────────────┘                   │                                │
                                               │  ┌─────────────┐               │
┌──────────────────────────┐   WebSocket/MCP   │  │ Tool Registry│               │
│  ai-scraping-defense-iis │ ─────────────────► │  └──────┬──────┘               │
│  (.NET / IIS)            │                   │         │                      │
└──────────────────────────┘                   │  ┌──────▼──────────────────┐   │
                                               │  │  Engines                │   │
                                               │  │  ├── RuleEngine         │   │
                                               │  │  ├── Scorer             │   │
                                               │  │  ├── AnomalyEngine      │   │
                                               │  │  └── PolicyEngine       │   │
                                               │  └─────────────────────────┘   │
                                               │                                │
                                               │  Integrations (optional)       │
                                               │  ├── Redis (cache)             │
                                               │  ├── PostgreSQL (audit/FB)     │
                                               │  └── GeoIP (MMDB)              │
                                               └────────────────────────────────┘
```

## Request Lifecycle

1. Client opens a WebSocket connection to `ws://<host>:8085/mcp`.
2. Server authenticates the connection using the `Authorization` header (token scheme).
3. Client sends a JSON-RPC 2.0 message: `{ "jsonrpc": "2.0", "id": 1, "method": "classify", "params": {...} }`.
4. Server acquires a semaphore permit (global concurrency control).
5. Tool is dispatched through the registry with a per-tool timeout.
6. Engines evaluate the request: rules → scorer → anomaly → policy.
7. Response is serialized and returned over the WebSocket.
8. Metrics and audit logs are emitted.

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
| `mcp/protocol` | `src/mcp/protocol.rs` | JSON-RPC 2.0 message types |
| `mcp/tool_registry` | `src/mcp/tool_registry.rs` | Tool registration + dispatch |
| `engines/rules` | `src/engines/rules.rs` | Pattern-based signal extraction |
| `engines/scorer` | `src/engines/scorer.rs` | Score aggregation + verdict |
| `engines/explain` | `src/engines/explain.rs` | Human-readable explanations |
| `engines/anomaly` | `src/engines/anomaly.rs` | Statistical anomaly detection |
| `engines/policy` | `src/engines/policy.rs` | Configurable decision thresholds |
| `tools/*` | `src/tools/` | All 23 MCP tool implementations |
| `integrations/*` | `src/integrations/` | Redis, PostgreSQL, GeoIP adapters |
| `util/*` | `src/util/` | Time, JSON, network, hashing helpers |

## Concurrency Model

- **Async runtime**: Tokio with `rt-multi-thread`
- **Global concurrency**: `tokio::sync::Semaphore` with configurable limit (default 256)
- **Per-tool timeout**: wraps each dispatch with `tokio::time::timeout`
- **Cache**: Moka in-process LRU cache (async, bounded capacity)
- **Backpressure**: semaphore blocks new requests when all permits are taken

## Observability

- **Logging**: `tracing` + `tracing-subscriber` with JSON formatter
- **Metrics**: Prometheus counters/histograms exposed at `/metrics`
  - `mcp_requests_total{tool, status}`
  - `mcp_request_duration_seconds{tool}` (p50/p95/p99 via histogram)
  - `mcp_active_connections`
  - `mcp_tool_errors_total{tool, error_code}`
- **Health**: `GET /health` (liveness), `GET /ready` (readiness)
- **OTLP**: Optional OpenTelemetry export via `MCP__TELEMETRY__OTLP_ENDPOINT`
