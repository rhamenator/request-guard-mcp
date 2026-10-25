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

The server runs a best-effort `warmup` call at startup. Its rule regexes use
`once_cell::sync::Lazy` and compile on first use; there is no JIT compiler.
The `rule_engine` and `scorer` warmup targets run synthetic classification;
the `cache` target writes a marker into the local cache. Warmup does not prove
Redis health or that every engine was exercised on a cold path.

Classification evaluates rules before checking the cache. A hit can skip the
scoring step, but not rule evaluation. The fingerprint includes the
authenticated caller scope, the rule-relevant request fields, a cache schema
domain, recorded build version/commit and configured known-bad TLS set. A
three-field `(ip, user_agent, path)` match alone does not imply a cache hit.
JSON deserialization and signal construction allocate memory; no zero-copy or
allocation-free hot-path guarantee has been established.

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
TOKIO_WORKER_THREADS=8 ./request-guard-mcp
```

## Metrics

Monitor these Prometheus metrics for performance insights:

- `mcp_request_duration_seconds{tool="classify"}` histogram → p50/p95/p99 latency
- `mcp_requests_total{tool, status}` → throughput and error rate
- `mcp_active_connections` → WebSocket connection pool pressure

## Redis Caching

When Redis is configured, the classify path attempts a Redis lookup before
the in-process Moka cache. Redis failures fall back to the local cache. Cache
identity includes the caller and all rule-relevant request fields, so use a
representative request mix when measuring hit rate. The local TTL is 300
seconds; Redis defaults to 300 seconds and is configurable with
`MCP__REDIS__CACHE_TTL_SECS`. Check backend latency as well as hit rate.

## Resource Sizing

Measure CPU, memory, p95/p99 latency and backend load under your own request
mix and concurrency limit before sizing replicas. The private 512 MiB
container qualification checks bounded wide-JSON and slow-header behavior; it
does not establish requests-per-second capacity or a production replica count.
