# Security Model

## Authentication

All WebSocket connections are authenticated at connection establishment using token-based authentication (HTTP ******

- The `Authorization` header (in ****** format) must be present on the WebSocket upgrade request.
- Tokens are configured via the `AUTH_TOKENS` environment variable (comma-separated).
- An unauthenticated connection receives a JSON-RPC error and the connection is closed.
- Authentication is enforced before any tool dispatch occurs.

## Transport Security

- In production, place the server behind a TLS-terminating reverse proxy (nginx, Envoy, or a cloud load balancer).
- The server itself speaks plain WebSocket (`ws://`) internally.
- Kubernetes NetworkPolicy restricts ingress to the `ai-defense` namespace only.

## Input Validation

- All request bodies are size-limited (`max_request_bytes`, default 1 MiB).
- All tool parameters are deserialized into strongly-typed structs via `serde`.
- Invalid JSON is rejected with a `Parse error` (-32700) response.
- Batch requests are bounded by `max_batch_size` (default 50).
- Per-tool timeouts prevent slow-loris and resource exhaustion attacks.

## No Panics on Request Path

- All engine code returns `Result<_, AppError>` and handles errors gracefully.
- `AppError` variants carry non-leaky messages for clients.
- Internal details are logged server-side but not exposed to clients.

## Log Redaction

- The `redact_preview` tool and `util::json::redact_fields` redact known sensitive fields before logging.
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
- When the semaphore is saturated, new requests receive a `RATE_LIMIT_EXCEEDED` error immediately.
- Per-tool timeouts (configurable per tool) prevent long-running requests from holding permits.

## Audit Logging

Every tool invocation logs:
- `tool` name
- `latency_ms`
- `outcome` (ok / error / timeout)
- `error_code` (on failure)

Request IDs are propagated through the response for correlation.
