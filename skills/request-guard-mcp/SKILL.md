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

For v0.1.4, install the matching native release bundle and follow its bundled
`INSTALL.md`, or use `npm install -g request-guard-mcp@0.1.4` once that package
is available on npm. Linux x64 has separate glibc and musl/Alpine bundles;
Windows x64, macOS Intel, and macOS Apple Silicon are also packaged. Verify
native archive checksums. The skill ZIP contains instructions only. Configure
a unique `AUTH_TOKENS` bearer token of at least 32 characters, start the
server, and connect an HTTP POST MCP client to `/mcp` with that token. Confirm
`tools/list` includes `classify` and `explain` before using the skill. Release
CI runs official MCP Inspector 2.5.0 against the native bundles; check your
chosen client separately. Redis, PostgreSQL, and MaxMind data are optional for
core tools but required by some additional tools and may incur costs.

The server supports HTTP POST JSON-RPC and a custom WebSocket transport. It
does not offer stdio, SSE GET, OAuth discovery, MCP resources or prompts. For
HTTP POST, send `Content-Type: application/json` and
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
- For a batch of observed requests, call `batch_classify` if available. To explain a specific result, retain the original request metadata passed to `classify` and pass that same metadata to `explain`; do not pass the classification response as input. Use `model_info` and `health` to check capability and service status before relying on an optional backend tool.
- Use enrichment, reputation, canary, replay, drift, or calibration tools only when the corresponding backend is configured and the user's task calls for that evidence. Report an unavailable backend as unavailable, not as a clean signal.
- PostgreSQL replay, feedback, drift, and calibration are limited to the authenticated caller's own decisions. The server operator must configure a stable `CACHE_SCOPE_HMAC_KEY` with PostgreSQL so records remain available after restart.
- Starting with v0.1.4, PostgreSQL TLS verification uses the operating system CA store. For a private database CA, the operator can install it there or set `sslrootcert=/path/to/ca.pem` in `MCP__POSTGRES__URL` and use `sslmode=verify-full` for chain and hostname verification. Minimal container and Alpine hosts need a populated CA store unless that private CA is supplied. A configured PostgreSQL connection with an untrusted certificate or hostname mismatch prevents server startup. `sslmode=require` encrypts without certificate verification.
- Configuration snapshots are redacted. Do not request `redact_secrets:false`; the server rejects unredacted snapshots.
- If a tool call returns `RATE_LIMIT_EXCEEDED`, treat it as temporary capacity pressure; retry later with bounded backoff rather than assuming the request is safe or sending a burst of retries.
- Incomplete or slow HTTP requests can receive HTTP 408, and new sockets can be closed when the server's connection cap is full. Treat either as an availability signal, not an allow verdict.
- On v0.1.2 and newer builds, WebSocket close code 1009 means a frame or fragmented message exceeded the configured request limit. Published v0.1.1 may instead close that connection without a close frame.

Record the returned request ID, verdict, confidence, and contributing signals. User-agent strings are self-declared, so a bot-name signal is a heuristic rather than proof of identity. TLS fingerprints supplied by an ordinary caller are unverified without the server's attestation path; never invent that provenance. The result supports a site owner's policy decision. A website must explicitly send requests to the classifier and enforce its own response; this skill cannot route live traffic or block a visitor by itself.
Sensitive-path checks account for common percent encoding and backslash spellings, including `/internal` and `/xmlrpc.php`, but a verdict does not replace the website's own URL normalization or authorization rules. Scanner user-agent signals (such as masscan, Nikto, sqlmap, and HttpClient) are heuristics because callers can spoof or omit that header.
