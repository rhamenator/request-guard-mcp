# Architecture

## Overview

`request-guard-mcp` is a production-ready **Model Context Protocol (MCP) server** implemented in Rust. It provides a unified, high-performance request classification and enrichment API for any client that can speak WebSocket or HTTP JSON-RPC. The `ai-scraping-defense` Python, IIS, and Rust projects are compatible clients, but they are not required dependencies.

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

1. Client opens a WebSocket connection or sends an HTTP POST to `/mcp`.
2. Server authenticates the request using the `Authorization` header (Bearer scheme).
3. Client sends a JSON-RPC 2.0 message: `{ "jsonrpc": "2.0", "id": 1, "method": "classify", "params": {...} }`.
4. Server acquires a semaphore permit (global concurrency control).
5. Tool is dispatched through the registry with a per-tool timeout.
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
| `mcp/protocol` | `src/mcp/protocol.rs` | JSON-RPC 2.0 message types |
| `mcp/tool_registry` | `src/mcp/tool_registry.rs` | Tool registration + dispatch |
| `engines/rules` | `src/engines/rules.rs` | Pattern-based signal extraction |
| `engines/scorer` | `src/engines/scorer.rs` | Score aggregation + verdict |
| `engines/explain` | `src/engines/explain.rs` | Human-readable explanations |
| `engines/anomaly` | `src/engines/anomaly.rs` | Statistical anomaly detection |
| `engines/policy` | `src/engines/policy.rs` | Configurable decision thresholds |
| `tools/*` | `src/tools/` | All 23 MCP tool implementations |
| `integrations/*` | `src/integrations/` | Redis, PostgreSQL, MaxMind, reputation adapters |
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
- **OTLP**: Optional batched OpenTelemetry trace export via `MCP__TELEMETRY__OTLP_ENDPOINT`
