---
name: request-guard-mcp
description: Use a connected request-guard-mcp server to classify observed HTTP request metadata, explain its verdicts, and inspect its available abuse signals. Applies to this MCP server, not to deploying the separate AI Scraping Defense products or guarding agent outbound fetches.
---

# Request Guard MCP

This companion skill tells an agent when and how to use the separately
installed Request Guard MCP server for **inbound** HTTP request classification.
It does not include the server binary, intercept live traffic, enforce a site
policy, or guard the agent's outbound fetches. Stable release readiness still
depends on the repository's adversarial release gate.

For v0.1.5, install the matching native release bundle and follow its bundled
`INSTALL.md`, or install the verified `request-guard-mcp@0.1.5` npm package.
The npm package passed a fresh public-registry Inspector and stdio smoke;
v0.1.4 on npm lacks stdio. Linux x64 has
separate glibc and musl/Alpine bundles;
Windows x64, macOS Intel, and macOS Apple Silicon are also packaged. Verify
native archive checksums. The skill ZIP contains instructions only. For HTTP
or custom WebSocket, configure a unique `AUTH_TOKENS` bearer token of at least
32 characters, start the server, and connect the client to `/mcp` with that
token. Confirm every example bearer, HMAC, TLS attestation, and backend password has been
replaced before deployment; published v0.1.5 does not reject the shipped HMAC
or attestation placeholders. Then confirm `tools/list` includes `classify` and
`explain` before using the skill.
Store the server `.env` and any token files so only the server account and
authorized administrators can read them. On Linux/macOS, create `.env` under
`umask 077` and verify mode 0600; on Windows, check its NTFS ACL before adding
secrets. Development-main native `INSTALL.md` gives these steps explicitly;
published v0.1.5 bundles predate that wording.
The release workflow is configured to run official MCP Inspector 2.11.0 on
future native bundles. Published v0.1.5 bundles were built with the prior
2.5.0 smoke; a separate 2.11.0 smoke passed on the exact public Linux x64
binary. The exact
public v0.1.4 Linux binary also passed deterministic HTTP and custom WebSocket
envelope probes; check any other chosen client separately. Optional SSE is
not implemented. Redis, PostgreSQL, and MaxMind data are optional for core
tools but required by some additional tools and may incur costs.
Development main bounds best-effort Redis operation records to 500 ms each;
published v0.1.5 can wait longer when configured Redis stalls. A timed-out
record may be absent from `queue_status` or show as active until Redis
trim/expiry; Redis-dependent tools still need a healthy backend.
`queue_status` is best-effort operation telemetry: `depth` counts observed
in-flight tools rather than waiting work, and `consumers` is the configured
global concurrency ceiling rather than free workers. A zero result for a
requested name does not prove that name exists or that ingress is healthy.
Development main also bounds concurrent Redis/PostgreSQL pings on the unauthenticated
`/health` and `/ready` endpoints to one second per request. A stalled backend
makes `/health` return HTTP 200 with an unhealthy JSON status, and `/ready` return HTTP 503.
Published v0.1.5 does not have this bound. Restrict those endpoints at a proxy.
For a local stdio client on v0.1.5, set the client's command to the installed
native executable and its arguments to
`["--stdio"]`, then verify
`tools/list` before using this skill. The client owns the child process;
stdin/stdout carry one JSON-RPC message per line and diagnostics go to stderr.
No HTTP listener or bearer token protects this channel, so grant process and
environment access only to trusted local users. Automatic `.env` discovery
is disabled; pass optional configuration explicitly. Calls are sequential;
there is no request cancellation or session resumption. PostgreSQL integration
is unavailable in stdio mode. Private five-platform packaged smoke,
an official Python SDK 2.3.0 client, and a clean npm-installed Linux launcher
passed before release; this does not establish support for every client.
When using the published v0.1.5 npm launcher in HTTP mode, forcibly killing
only the Node wrapper can leave its native listener running; stop the native
child or process group too. Development HTTP launchers use a private parent
pipe so a forcibly killed wrapper starts a bounded native drain. Forced-kill
cleanup on macOS and Windows is being qualified on packaged builds.
The earlier v0.1.3 release supports
standard MCP initialization and tool calls but predates the v0.1.4 Origin,
HTTP status/header, JSON-RPC envelope, and PostgreSQL native CA changes below.
Use its [tagged installation instructions](https://github.com/rhamenator/request-guard-mcp/tree/v0.1.3)
when operating v0.1.3; do not assume the following v0.1.4 checks apply to it.

v0.1.5 supports HTTP POST JSON-RPC, a custom WebSocket transport, and local
stdio. It does not offer SSE GET, OAuth discovery, MCP resources or prompts. For
development main, custom WebSocket uses HTTP/1 upgrade; HTTP/2 extended CONNECT
is disabled. For HTTP POST, send `Content-Type: application/json` and
`Accept: application/json, text/event-stream`. After initialization, send
`MCP-Protocol-Version: 2025-06-18`; an explicit invalid version gets HTTP 400.
Explicit unsupported content types get 415 and an `Accept` that excludes JSON
gets 406. Missing headers remain accepted for older direct clients. An
authenticated ordinary GET to `/mcp` gets 405. Accepted HTTP notifications
and client responses get 202 with no body; do not treat that as a verdict.

Use JSON-RPC `2.0` with a string or integer request ID, never `null` or a
fraction. When supplied, request or notification `params` must be an object.
A client success-response `result` must be an object with a matching valid
ID. Treat protocol errors as invalid calls, not classification verdicts.
Browser-originated HTTP POST or WebSocket requests need an exact
`MCP_ALLOWED_ORIGINS` entry in addition to bearer authentication. The
allowlist does not enable CORS: cross-origin browser clients require a trusted
proxy for preflight handling; browser WebSocket clients need that proxy to
authenticate and set the upstream bearer header. Origin is not authentication.

## When and how

- For an observed inbound website or API request that needs a risk assessment, call `classify` with only relevant metadata, such as `ip`, `user_agent`, `method`, `path`, and selected headers. Configure the MCP client's bearer token; unauthenticated HTTP POST requests are rejected before their body is read. Avoid sending request bodies, cookies, authorization headers, and personal data unless the task requires them and the user has authorized that transfer.
- Avoid large arbitrary `extra` objects or arrays. Development main rejects messages with more than 16,384 JSON structural separators/containers before parsing; published v0.1.5 has a byte limit but not this complexity guard.
- For a batch of observed requests, call `batch_classify` if available. Inspect the top-level `errors` count and each item error before using results. On development main, set `options.include_details` to `false` to omit per-item signal details; omitting it keeps the full response. Published v0.1.5 accepts but ignores this option, so inspect returned signals before sharing batch results.
- For a diagnostic rule-engine score on development main, pass inbound request metadata as the nested `score_breakdown` `signals` object, for example `{"signals":{"user_agent":"GPTBot/1.0","path":"/"}}`. Do not pass a raw signal array or treat this diagnostic as the live `classify` verdict. Development main rejects malformed supplied `signals`; published v0.1.5 may instead report zero.
- To explain a specific result, retain the same request metadata fields sent to `classify`. Pass them inside the required `explain` arguments object, for example `{"classification":{"ip":"192.0.2.1","user_agent":"GPTBot/1.0","path":"/"}}`. `classify` takes flat arguments; `explain` requires this nested shape. Do not pass the classification response as `classification`.
- Use `model_info` and `health` to check capability and service status before relying on an optional backend tool.
- `abuse_pattern_match` returns heuristic text signals, not a block decision. If filtering categories on development main, use `injection`, `traversal`, `ai_attack`, or `data_extraction`; unknown categories return an error and ASCII case variants are accepted. Published v0.1.5 can instead return a false-clean result for an unknown category or multiline SQL text, so do not rely on it as a sole detector.
- `validate_payload` checks whether a named tool and payload have the callable request shape. Development main also checks supported `feature_flags.flag` and `warmup.target` names. Errors use root path `/`. A valid result does not execute the tool or establish that an optional feature or backend is available.
- On development main, `self_test` accepts an omitted `suite` or `"all"`; any other suite is rejected. Published v0.1.5 may silently run all checks for an unsupported suite, so do not treat that result as proof the requested suite ran.
- Use enrichment, reputation, canary, replay, drift, or calibration tools only when the corresponding backend is configured and the user's task calls for that evidence. Report an unavailable backend as unavailable, not as a clean signal.
- On development main, `enrich_ip` treats IPv6 unique-local/link-local and mapped private IPv4 addresses as local without an optional backend; `enrich_ip` and `threat_lookup` check the IPv4 Redis key before the literal mapped key for IPv4-mapped IPv6 input. Published v0.1.5 lacks this correction. This enrichment behavior does not change the inbound `classify` verdict.
- On development main, seed new IPv6 Redis threat keys in canonical compressed spelling. For valid noncanonical IPv6 input, `enrich_ip` and `threat_lookup` check the canonical key before that exact supplied spelling for a legacy record. They do not search every alias; migrate older keys so callers need not know the seeded spelling. Published v0.1.5 lacks this fallback.
- `threat_lookup` needs configured Redis. Its `found:false` means no matching record, not a safe indicator. Always pass `type` for hash and ASN indicators. On development main, name that field exactly, use lowercase ASCII domain keys without a trailing DNS dot (send internationalized domains as punycode), and use exact lowercase-scheme URL keys. Unknown fields and ambiguous URL/domain spellings are rejected; published v0.1.5 lacks these checks.
- `redact_preview` replaces exact JSON keys case-insensitively, including nested keys. On development main, `fields_redacted` lists only keys actually replaced and misspelled request fields are rejected; published v0.1.5 can misreport this list. Custom `fields` replace the defaults, and text inside string values is not parsed or redacted. Inspect the returned payload before sharing it.
- `enrich_ua` parses a user-agent and provides a diagnostic score, not an inbound verdict. On development main the score also reflects broad rule-engine AI-bot and scraper patterns, including generic HTTP client strings; false positives are possible. Published v0.1.5 can score sqlmap, Nikto or masscan at 0.1. `is_bot` only reflects the parser's crawler category, so `false` does not rule out automation. For a request decision, use `classify`; user-agent strings can be spoofed.
- PostgreSQL replay, feedback, drift, and calibration are limited to the authenticated caller's own decisions. The server operator must configure a stable `CACHE_SCOPE_HMAC_KEY` with PostgreSQL so records remain available after restart.
- Development main avoids repeat PostgreSQL table DDL on startup when the schema is already current. Initial setup and older-schema migration still take table locks; schedule those changes during a quiet write window. Published v0.1.5 lacks this fast path.
- Use a fresh `request_id` for each distinct classification. On development main, reusing an ID replaces that caller's persisted decision; changed replay inputs or response clear old feedback, while an equivalent retry keeps it. Submit feedback again for a changed decision. Published v0.1.5 can carry old feedback onto a replacement. Upgrading does not repair existing stale labels.
- Published v0.1.5 stores the full classification request in PostgreSQL when persistence is enabled. Development main minimizes future replay request JSON to current rule inputs and omits header values, bodies, arbitrary `extra`, IP, referrer, timestamp, request ID and TLS attestation material; the stored response still holds the request ID, verdict and signals. Existing rows are not rewritten automatically. Paths and user agents can still contain personal data, so avoid sending secrets and set an operator-managed decision retention/deletion schedule. Replay of an attested TLS fingerprint may differ after its short-lived provenance expires.
- Keep request IDs nonsecret. Published v0.1.5 may write a caller-supplied ID to a tool-error warning; development main logs only the categorical tool error code. This does not redact other server or backend diagnostics.
- Starting with v0.1.4, PostgreSQL TLS verification uses the operating system CA store. For a private database CA, the operator can install it there or set `sslrootcert=/path/to/ca.pem` in `MCP__POSTGRES__URL` and use `sslmode=verify-full` for chain and hostname verification. Minimal container and Alpine hosts need a populated CA store unless that private CA is supplied. With `sslmode=verify-full`, an untrusted certificate or hostname mismatch prevents server startup. `sslmode=require` encrypts without certificate verification.
- Redis is optional and v0.1.5/development main support plaintext `redis://` only. `rediss://` fails startup rather than downgrading. A Redis password is not transport encryption. The server operator must keep Redis on a trusted isolated local/private link or terminate an independently secured tunnel at loopback; otherwise leave Redis unconfigured. For production PostgreSQL across a network, use `sslmode=verify-full` and a trusted CA rather than copying the local demo URL.
- Redis canary registry records and the last 10,000 canary events have no automatic time-based expiry in v0.1.5 or development main. When caller context encodes to at most 4096 bytes, a matched `canary_eval` stores that JSON value unredacted in a shared Redis event, without PostgreSQL's per-caller scope. Do not submit secrets or unnecessary personal data as context; ask the server operator for the Redis event retention/purge policy. Cache and queue TTLs do not apply to canary records.
- When supplying optional canary context, use exactly the `context` argument, for example `{"token":"canary-token-value","context":{"path":"/protected"}}`. Development main rejects unknown top-level `canary_eval` fields; published v0.1.5 may silently ignore a misspelling and omit the context from the Redis event.
- Development main separates cached classification verdicts by recorded source commit, version, cache schema marker, and configured known-bad TLS fingerprints. This partition covers those inputs only; reassess cache identity if future runtime settings affect verdicts. Local builds with `unknown` commit metadata or uncommitted source changes need a new Redis key prefix or cache clearing after classification source changes. Published v0.1.5 lacks this partition; a v0.1.5 replica can return an earlier verdict during a rolling upgrade or after a threat-set change for up to its configured TTL. A patched build does not read those old keys. Ask the operator to coordinate such changes and keep cache TTL appropriate for the deployment.
- Configuration snapshots are redacted. Do not request `redact_secrets:false`; the server rejects unredacted snapshots.
- Development main rejects misspelled `feature_flags`, `warmup`, and `config_snapshot` arguments and unsupported named flags or warmup targets. Published v0.1.5 may silently ignore a misspelled argument, treat an unknown flag as disabled, or list an unknown warmup target as skipped. `feature_flags` describes startup state, while `warmup` is best effort and does not check Redis health; use `/ready` for live readiness.
- If a tool call returns `RATE_LIMIT_EXCEEDED`, treat it as temporary capacity pressure; retry later with bounded backoff rather than assuming the request is safe or sending a burst of retries.
- Incomplete or slow HTTP/1 requests can receive HTTP 408, and new sockets can be closed when the server's connection cap is full. Development main closes connections that send no complete first request by the header deadline, including incomplete HTTP/2 setup; it stops admitting non-upgraded HTTP/1 requests about 120 seconds after the first request, gives in-flight responses a bounded drain, and closes an HTTP/1 keep-alive connection after 128 requests. A non-reading peer can lose its response at the drain deadline. It closes HTTP/2 connections after idle time (`MCP__LIMITS__HTTP2_IDLE_TIMEOUT_SECS`, default 60 seconds), 120 seconds of age, or 128 requests. WebSocket upgrades use separate limits. Published v0.1.5 lacks these HTTP/1 age/request and HTTP/2 protections. An active peer can reconnect; use proxy connection, read, and rate limits as an additional boundary. Treat timeout and shedding responses as availability signals, not allow verdicts.
- On v0.1.2 and newer builds, WebSocket close code 1009 means a frame or fragmented message exceeded the configured request limit. Published v0.1.1 may instead close that connection without a close frame. Development main may close a WebSocket whose client does not read an outgoing response within five seconds; published v0.1.5 lacks this send deadline. Reconnect and retry only when your workflow can safely repeat the request.
- On development main with at least two distinct configured bearer tokens, one bearer can use no more than `MCP__LIMITS__MAX_CONNECTIONS - 1` concurrent WebSocket slots when the global cap is above one. A same-bearer excess upgrade receives HTTP 503. A single-token deployment keeps the full global cap. Published v0.1.5 has no per-bearer WebSocket cap. Clients sharing a bearer should use bounded reconnect/backoff; operators still need ingress connection and rate limits for distributed fairness.
- Development main stops new network admission on SIGTERM or Ctrl-C and gives active HTTP responses a bounded drain before process exit. Existing WebSocket sessions end on process exit and need a new connection. Published v0.1.5 has no SIGTERM drain. If a response is interrupted, retry only when the operation is safe to repeat.

Record the returned request ID, verdict, confidence, and contributing signals. User-agent strings are self-declared, so a bot-name signal is a heuristic rather than proof of identity. TLS fingerprints supplied by an ordinary caller are unverified without the server's attestation path; never invent that provenance. The result supports a site owner's policy decision. A website must explicitly send requests to the classifier and enforce its own response; this skill cannot route live traffic or block a visitor by itself.
Sensitive-path checks account for common percent encoding and backslash spellings, including `/internal` and `/xmlrpc.php`, but a verdict does not replace the website's own URL normalization or authorization rules. Scanner user-agent signals (such as masscan, Nikto, sqlmap, and HttpClient) are heuristics because callers can spoof or omit that header.
