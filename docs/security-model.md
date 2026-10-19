# Security Model

## Authentication

All WebSocket connections are authenticated at connection establishment using a bearer token in the HTTP `Authorization` header.

- The `Authorization` header (`Bearer <token>`) must be present on the WebSocket upgrade request.
- Tokens are configured via the `AUTH_TOKENS` environment variable (comma-separated).
- An unauthenticated connection receives a JSON-RPC error and the connection is closed.
- Authentication is enforced before any tool dispatch occurs.
- Classification caches are partitioned by a server-derived, HMAC-SHA256-keyed
  digest of the authenticated credential; raw bearer tokens are never used in
  cache keys, and the keyed digest cannot be dictionary-attacked from Redis key
  listings without the server-side key. Configure `CACHE_SCOPE_HMAC_KEY`
  (>= 32 bytes) to keep scopes stable across restarts and replicas; otherwise a
  process-local random key is used.
- PostgreSQL decision, replay, feedback, drift, and calibration records are
  partitioned by the authenticated caller scope. `CACHE_SCOPE_HMAC_KEY` is
  required with PostgreSQL so a caller's scope remains stable after restart.
  Existing records created before this partitioning are retained in the
  database but are not exposed through caller-scoped tools; migrate or archive
  them offline before relying on historical reports.

## Transport Security

- In production, place the server behind a TLS-terminating reverse proxy (nginx, Envoy, or a cloud load balancer).
- The server itself speaks plain WebSocket (`ws://`) internally.
- Kubernetes NetworkPolicy restricts ingress to the `request-guard`, `ai-defense`, and `default` namespaces by default. Tighten this allowlist for your deployment.

## Input Validation

- All request bodies are size-limited (`max_request_bytes`, default 1 MiB).
- All tool parameters are deserialized into strongly-typed structs via `serde`.
- Invalid JSON is rejected with a `Parse error` (-32700) response.
- Batch requests are bounded by `max_batch_size` (default 50).
- Per-tool timeouts bound tool execution after dispatch. They do not bound HTTP
  header or body read time; deploy a proxy with connection and read timeouts.
- Caller-supplied JA3/JA4 values are format-validated metadata, not proof of a
  TLS handshake. Only a fresh, context-bound HMAC from a trusted producer sets
  server-derived `tls_fingerprint_verified`; only verified values affect rules
  and cache identity. See [TLS fingerprint attestation](tls-fingerprint-attestation.md).

## No Panics on Request Path

- All engine code returns `Result<_, AppError>` and handles errors gracefully.
- `AppError` variants carry non-leaky messages for clients.
- Internal details are logged server-side but not exposed to clients.

## Log Redaction

- The `redact_preview` tool and `util::json::redact_fields` can redact known
  sensitive fields when called. They are not a global log-redaction filter.
- Authorization headers and token values are never logged.
- IP addresses are logged at DEBUG level only; production uses `LOG_LEVEL=info`.

## Dependency Security

- `cargo audit` runs in CI to check for known vulnerabilities.
- `cargo deny` enforces license allowlists and blocks duplicate/yanked crates.
- Container image is scanned with Trivy in the security workflow.
- Base image: `debian:bookworm-slim` (minimal attack surface).
- Process runs as a non-root user (`mcp`, UID 10001).
- `readOnlyRootFilesystem: true` in Kubernetes pod spec.
- All Linux capabilities dropped in the pod security context.

## Rate Limiting and Backpressure

- Global semaphore prevents more than `global_concurrency` concurrent in-flight requests.
- When tool capacity is saturated, new tool calls receive a
  `RATE_LIMIT_EXCEEDED` error without waiting for a permit. This limit applies
  after HTTP body receipt and authentication; it is not a connection limit.
- Per-tool timeouts (configurable per tool) prevent long-running requests from holding permits.
- Unknown tool names are rejected before Redis operation bookkeeping and use a
  single `__unknown__` metrics label. Arbitrary caller-chosen names do not
  create unbounded Prometheus series or Redis queue keys.

## Audit Logging

Every tool invocation logs:
- `tool` name
- `latency_ms`
- `outcome` (ok / error / timeout)
- `error_code` (on failure)

Request IDs are propagated through the response for correlation.
