# Security Model

## Authentication

With `auth.enabled=true` (the default), the network MCP endpoint `/mcp`
requires a bearer token in the HTTP `Authorization` header for both JSON POST
requests and custom WebSocket GET upgrades. Tokens are configured via the
comma-separated `AUTH_TOKENS` environment variable. A missing token
gets HTTP 401; an invalid token gets HTTP 403. Both are rejected before POST
dispatch or WebSocket upgrade, so no WebSocket session or JSON-RPC message is
established. If an operator disables authentication, `/mcp` accepts
unauthenticated requests under a shared
`public` cache scope; restrict network access accordingly. Process-local
`--stdio` does not use bearer tokens or start a network listener. The local
client process and its access to the executable and configuration form its
trust boundary.

- With authentication enabled, it is enforced before any `/mcp` tool dispatch.
- `/health`, `/ready`, and the configured metrics endpoint are reachable without
  a bearer token. Limit access to these operational endpoints at the network
  or reverse proxy boundary.
- Classification caches are partitioned by a server-derived, HMAC-SHA256-keyed
  digest of the authenticated credential; raw bearer tokens are never used in
  cache keys, and the keyed digest cannot be dictionary-attacked from Redis key
  listings without the server-side key. Configure `CACHE_SCOPE_HMAC_KEY`
  (>= 32 bytes) to keep scopes stable across restarts and replicas; otherwise a
  process-local random key is used.
- Development main also partitions classification cache entries by recorded
  source commit, version, cache schema marker, and normalized known-bad TLS
  fingerprint configuration. Only these inputs are partitioned; reassess cache
  identity if future runtime settings affect verdicts. Local builds with
  `unknown` commit metadata or uncommitted source changes must use a new Redis
  key prefix or clear old cache entries after classification source changes.
  Published v0.1.5 lacks this partition: a v0.1.5 replica can continue serving
  its cached verdict during a rolling upgrade or after a threat-set change,
  until the configured TTL expires (300 seconds by default). A patched build
  does not read those old keys. Cache partitioning does not replace deployment
  coordination.
- PostgreSQL decision, replay, feedback, drift, and calibration records are
  partitioned by the authenticated caller scope. `CACHE_SCOPE_HMAC_KEY` is
  required with PostgreSQL so a caller's scope remains stable after restart.
  Development main removes older feedback in the same transaction when the
  same caller replaces a decision with changed stored replay inputs or
  response under a reused request ID. An equivalent retry keeps feedback.
  Published v0.1.5 does not clear old feedback on replacement, and upgrading
  does not repair already stale labels automatically.
  Existing records created before this partitioning are retained in the
  database but are not exposed through caller-scoped tools; migrate or archive
  them offline before relying on historical reports.
- Development main minimizes new PostgreSQL replay request JSON to a subset
  of current rule inputs and header-name presence; it does not persist caller-provided
  header values, body snippets, arbitrary extra data, IPs, referrers,
  timestamps, request IDs or TLS attestation material in that request JSON. Stored verdicts,
  signals and response request IDs remain. Paths, user agents, request IDs and feedback can still
  contain personal data. The schema has no automatic retention; operators must
  schedule deletion. Upgrading does not automatically rewrite older full-payload
  rows; a reviewed, one-time operator migration is available at
  `scripts/postgres_minimize_legacy.sql`.
  Published v0.1.5 still stores full classification requests.
- Optional Redis supports plaintext `redis://` only in published v0.1.5 and
  development main; `rediss://` fails startup. Keep Redis on a trusted isolated
  link or an independently secured loopback tunnel, or leave it unconfigured.
  A Redis password does not encrypt the connection. In both published v0.1.5
  and development main, canary registry records and the event list have no
  automatic time-based expiry; the list is capped at 10,000 events by count. A
  matched `canary_eval` can store caller-provided context whose JSON encoding
  is at most 4096 bytes, unredacted in a shared event and without
  PostgreSQL's caller scope.
  Operators must define Redis retention and purge; cache and queue TTLs do
  not expire canary records. Do not submit secrets or unnecessary personal
  data as canary context.

## Transport Security

- In production, place the server behind a TLS-terminating reverse proxy (nginx, Envoy, or a cloud load balancer).
- The server itself speaks plain WebSocket (`ws://`) internally.
- Kubernetes NetworkPolicy restricts ingress to the `request-guard`, `ai-defense`, and `default` namespaces by default. Tighten this allowlist for your deployment.

## Input Validation

- All request bodies are size-limited (`max_request_bytes`, default 1 MiB).
- Development main also rejects JSON messages with more than 16,384 structural
  separators/containers before allocating a `serde_json::Value`. This bounds
  wide arrays and objects that otherwise amplify memory despite a small byte
  count. Punctuation inside strings does not count. HTTP returns 413 before
  parsing; WebSocket and stdio use the existing JSON-RPC `-413` error with a
  null ID. Published
  v0.1.5 has only the byte limit; authorized callers should avoid large
  arbitrary `extra` values.
- All tool parameters are deserialized into strongly-typed structs via `serde`.
- Sensitive-path signals inspect up to four rounds of percent decoding and
  backslash separators. This is a heuristic; the deploying origin must still
  enforce its own URL normalization and access controls.
- Invalid JSON is rejected with a `Parse error` (-32700) response.
- Batch requests are bounded by `max_batch_size` (default 50).
- HTTP/1.1 header reads have a 10-second deadline by default; authenticated HTTP
  bodies have a 30-second deadline and a 1 MiB size limit by default. Both
  deadlines are configurable with `MCP__LIMITS__HTTP_HEADER_TIMEOUT_SECS` and
  `MCP__LIMITS__HTTP_BODY_TIMEOUT_SECS`. A body timeout returns HTTP 408.
- Development main closes a non-upgraded HTTP/1 keep-alive connection after
  128 requests and stops admitting requests at about 120 seconds after the
  first request. An in-flight response gets a bounded drain of the body
  deadline plus the larger tool/classify deadline and two seconds; stalled
  response writes are cut off at that drain deadline. At default limits, a
  non-reading peer can therefore retain a connection permit for about 182
  seconds total (120-second age plus at most 62 seconds of drain). The final
  non-upgrade response carries
  `Connection: close`; WebSocket upgrades remain subject to their separate
  limits. Published v0.1.5 lacks these HTTP/1 controls. A peer can reconnect,
  so use proxy connection, read, and rate limits as another boundary.
- HTTP/2 connections without a first complete request close after the header
  deadline. After a request completes, an idle HTTP/2 connection closes after
  `MCP__LIMITS__HTTP2_IDLE_TIMEOUT_SECS` (60 seconds by default). Development
  main also ends an HTTP/2 connection after 120 seconds or 128 requests, so
  repeated health requests and rapid stream resets cannot keep one permit
  indefinitely. Requests beyond the cap receive a 503 if hyper accepts them
  during GOAWAY; they are not dispatched to tools. MCP POST body reads and
  dispatched tools retain their separate
  deadlines; shutdown waits for GOAWAY completion up to the body deadline plus
  the larger tool/classify deadline and two seconds. Published v0.1.5 lacks
  these HTTP/2 protections. A proxy should also set connection and read limits.
  The idle deadline measures time since a handler returned its response rather
  than raw frame activity; a slow reader may lose a response body at the
  bounded shutdown deadline. HTTP/2 extended CONNECT/WebSocket is not enabled.
- Per-tool timeouts separately bound tool execution after dispatch. Deploy a
  proxy with connection and read limits as another boundary.
- On development main, SIGTERM or Ctrl-C stops new TCP accepts, asks idle HTTP
  connections to close, and rejects
  requests newly dispatched on existing HTTP connections with 503. Already
  dispatched HTTP responses have at most the body deadline plus the larger
  tool/classify deadline plus two seconds to complete; remaining connection
  tasks are then aborted and telemetry shutdown runs. Upgraded WebSocket
  sessions end when the process exits and must reconnect elsewhere. This does
  not guarantee completion of a slow response or delivery of an OTLP export.
  A second SIGTERM or Ctrl-C forces immediate exit without waiting for drain.
  The default drain can last about 62 seconds, so operators need at least 75
  seconds of orchestrator stop grace and must raise it when they increase the
  configured body or tool deadline. Published v0.1.5 has no process-level
  SIGTERM drain.
- Development main bounds each custom WebSocket response or control-frame send
  to five seconds. A client that stops reading may lose the response and its
  connection, releasing the WebSocket permit. Published v0.1.5 lacks this
  send deadline.
- Caller-supplied JA3/JA4 values are format-validated metadata, not proof of a
  TLS handshake. Only a fresh, context-bound HMAC from a trusted producer sets
  server-derived `tls_fingerprint_verified`; only verified values affect rules
  and cache identity. See [TLS fingerprint attestation](tls-fingerprint-attestation.md).

## Request-path error handling

- Fallible tool and integration operations return `Result<_, AppError>` and
  surface bounded protocol errors. A Rust panic aborts this release build;
  these checks do not prove that every request path is panic-free.
- `AppError` variants carry non-leaky messages for clients.
- Development main logs categorical tool error codes rather than rendered
  `AppError` text, which can include caller-supplied request IDs. Published
  v0.1.5 may log those IDs on tool errors and successful feedback; keep request
  IDs nonsecret. Other backend and transport diagnostics can still contain
  implementation details.
- `config_snapshot` never returns an OTLP endpoint or its embedded credentials;
  requests with `redact_secrets:false` are rejected.

## Log Redaction

- The `redact_preview` tool and `util::json::redact_fields` can redact known
  sensitive fields when called. They are not a global log-redaction filter.
- Authorization headers and token values are never logged.
- A DEBUG transport diagnostic can include the TCP peer socket address when
  an HTTP connection closes. That address is distinct from the client IP in a
  classification request; no classification-IP log is asserted for this path.
  `LOG_LEVEL=info` suppresses this DEBUG diagnostic. The blocklist's `add_ip`
  method has an INFO-level IP log if invoked; other integration logs are not a
  global redaction boundary. Keep submitted IPs and other metadata within your
  deployment's log/privacy policy.

## Dependency Security

- `cargo audit` runs in CI to check for known vulnerabilities.
- `cargo deny` enforces license and source allowlists; duplicate and yanked crates currently warn.
- Container image is scanned with Trivy in the security workflow.
- Base image: `debian:bookworm-slim` (minimal attack surface).
- Process runs as a non-root user (`mcp`); the Dockerfile does not pin its numeric UID.
- `readOnlyRootFilesystem: true` in Kubernetes pod spec.
- All Linux capabilities dropped in the pod security context.

## Rate Limiting and Backpressure

- Global semaphore prevents more than `global_concurrency` concurrent in-flight requests.
- A TCP admission semaphore caps in-progress HTTP connections, including
  clients that send no complete request headers. Excess sockets are closed at
  accept time. A separate WebSocket semaphore retains its own cap after an
  upgrade; the admission permit is released when the HTTP upgrade completes.
- Development main also limits one bearer to `max_connections - 1` concurrent
  WebSocket upgrades when at least two distinct bearer tokens are configured
  and the global cap exceeds one. It keys this local limit by the server's
  HMAC-derived caller scope, not by the bearer token. This reserves one global
  slot against a single Ping/Pong-active bearer; it does not provide a per-token
  guarantee against multiple cooperating bearers, replicas, or reconnects.
  Published v0.1.5 has no per-bearer WebSocket limit.
- When tool capacity is saturated, new tool calls receive a
  `RATE_LIMIT_EXCEEDED` error without waiting for a permit. This limit applies
  after HTTP body receipt and authentication; it is not a connection limit.
- Per-tool timeouts (configurable per tool) prevent long-running requests from holding permits.
- Unknown tool names are rejected before Redis operation bookkeeping and use a
  single `__unknown__` metrics label. Arbitrary caller-chosen names do not
  create unbounded Prometheus series or Redis queue keys.
- Development main limits each best-effort Redis tool-operation start and
  completion record to 500 ms. If a record times out, the core tool still
  runs; queue telemetry can temporarily omit the operation or show a stale
  active entry until its Redis trim/expiry. Published
  v0.1.5 does not include this bound. Redis-backed threat lookups and caching
  have their own availability behavior and are not covered by this limit.

## Metrics and diagnostic logs

Tool dispatch increments aggregate Prometheus counters by registered tool and
outcome (`ok`, `error`, or `timeout`) and observes a per-tool latency histogram.
Successful calls do **not** emit a per-invocation log entry. Tool errors emit a
categorical warning with the tool name and error code; timeouts emit an error
with the tool name and elapsed milliseconds. Request IDs are returned in
JSON-RPC responses but are not logged as caller identities. These metrics and
limited diagnostic events are **not** an audit trail and cannot reconstruct
which caller invoked a tool. Operators who need an audit trail must implement
one at their trusted ingress with explicit identity, access, redaction and
retention controls; do not log bearer tokens or raw request bodies.

The local Compose demo binds MCP, Prometheus and Grafana host ports to loopback.
Prometheus reads the unauthenticated MCP `/metrics` endpoint over the Compose
network. The demo backend links are plaintext and its pinned monitoring images
must be updated deliberately; do not expose this stack as a production network
boundary.
