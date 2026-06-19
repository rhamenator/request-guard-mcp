# Performance Tuning

## Key Configuration Knobs

| Setting | Env Var | Default | Effect |
|---------|---------|---------|--------|
| Global concurrency | `MCP__LIMITS__GLOBAL_CONCURRENCY` | 256 | Max in-flight requests |
| Classify timeout | `MCP__LIMITS__CLASSIFY_TIMEOUT_SECS` | 5 | Timeout for classify tool |
| Per-tool timeout | `MCP__LIMITS__PER_TOOL_TIMEOUT_SECS` | 30 | Timeout for other tools |
| Batch size | `MCP__LIMITS__MAX_BATCH_SIZE` | 50 | Max items in batch_classify |
| Request limit | `MCP__LIMITS__MAX_REQUEST_BYTES` | 1048576 | Max request body size |

## Classify Path Latency

The `classify` tool is the hottest path. Optimizations applied:

1. **Compiled regexes**: All patterns compiled once via `once_cell::sync::Lazy`, reused across requests.
2. **In-process LRU cache**: Moka cache keyed on `sha256(ip|user_agent|path)`. Cache hit avoids engine evaluation entirely.
3. **Zero-copy deserialization**: `serde_json` deserializes directly into typed structs.
4. **No heap allocations in hot path**: Signal vectors are pre-allocated with reasonable capacity.
5. **Warmup**: Call the `warmup` tool at startup (done automatically) to JIT-compile patterns.

## Tuning for High Throughput

```dotenv
# Increase concurrency for beefy hardware
MCP__LIMITS__GLOBAL_CONCURRENCY=1024

# Reduce classify timeout for tighter SLAs
MCP__LIMITS__CLASSIFY_TIMEOUT_SECS=2

# Raise batch size for bulk workloads
MCP__LIMITS__MAX_BATCH_SIZE=200
```

## Tokio Runtime

The server uses `#[tokio::main]` with the default `rt-multi-thread` flavor. Tokio uses one thread per CPU core by default.

To tune thread count:
```rust
// In main.rs (if needed)
#[tokio::main(worker_threads = 8)]
```

Or via environment:
```bash
TOKIO_WORKER_THREADS=8 ./ai-scraping-defense-mcp
```

## Metrics

Monitor these Prometheus metrics for performance insights:

- `mcp_request_duration_seconds{tool="classify"}` histogram → p50/p95/p99 latency
- `mcp_requests_total{tool, status}` → throughput and error rate
- `mcp_active_connections` → WebSocket connection pool pressure

## Redis Caching

When Redis is configured, the in-process Moka cache acts as L1 and Redis as L2 (not yet wired by default). To maximize hit rate:

- Ensure classify requests for the same `(ip, user_agent, path)` tuple are sent to the same server instance, or use Redis as a shared cache.
- TTL on cache entries is 300 seconds by default.

## Resource Sizing

| Load | CPU Request | Memory Request | Replicas |
|------|------------|----------------|---------|
| < 1k req/s | 100m | 128Mi | 2 |
| 1k–5k req/s | 250m | 256Mi | 3–5 |
| 5k–20k req/s | 500m | 512Mi | 5–10 |
| > 20k req/s | 1000m | 1Gi | 10+ with HPA |
