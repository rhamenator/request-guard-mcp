---
name: request-guard-mcp
description: Use a connected request-guard-mcp server to classify observed HTTP request metadata, explain its verdicts, and inspect its available abuse signals. Applies to this MCP server, not to deploying the separate AI Scraping Defense products or guarding agent outbound fetches.
---

# Request Guard MCP

This companion skill uses the server's implemented inbound request classification tools. It does not include the server binary or the proposed outbound `guarded_fetch` workflow. Stable release readiness still depends on the repository's adversarial release gate.

The published v0.1.2 Linux install requires glibc. Alpine/musl builds are under private qualification for a later release; do not direct an Alpine user to the v0.1.2 Linux binary or npm launcher.

Install the separate Request Guard MCP server from the [v0.1.2 native release bundle](https://github.com/rhamenator/request-guard-mcp/releases/tag/v0.1.2) and its `INSTALL.md`, or run `npm install -g request-guard-mcp@0.1.2` on a supported platform. The skill ZIP contains instructions only; it does not install, run, or host the server. Use v0.1.1 or a newer verified release with standard MCP `initialize`, `tools/list`, and `tools/call` support; the published v0.1.0 binary does not have those methods. Configure a unique `AUTH_TOKENS` bearer token of at least 32 characters, start the server, connect an HTTP POST MCP client to its `/mcp` endpoint with that token, and confirm `tools/list` includes `classify` and `explain` before using this skill. Release CI runs official MCP Inspector 2.5.0 against each native bundle; other clients need their own compatibility check. The server does not provide stdio, SSE GET, OAuth discovery, resources, prompts, or outbound egress control. Redis, PostgreSQL, and MaxMind data are optional for the core tools but required for some additional tools; obtaining and operating those services or data may incur costs. The AI Scraping Defense projects may use their own detection logic, this server, another MCP server, or no MCP server; do not change that choice on the user's behalf.
Send tool requests in a JSON-RPC `2.0` envelope with a string or numeric ID. Treat a JSON-RPC protocol error as an invalid call, not a classification verdict.

## When and how

- For an observed inbound website or API request that needs a risk assessment, call `classify` with only relevant metadata, such as `ip`, `user_agent`, `method`, `path`, and selected headers. Configure the MCP client's bearer token; unauthenticated HTTP POST requests are rejected before their body is read. Avoid sending request bodies, cookies, authorization headers, and personal data unless the task requires them and the user has authorized that transfer.
- For a batch of observed requests, call `batch_classify` if available. To explain a specific result, retain the original request metadata passed to `classify` and pass that same metadata to `explain`; do not pass the classification response as input. Use `model_info` and `health` to check capability and service status before relying on an optional backend tool.
- Use enrichment, reputation, canary, replay, drift, or calibration tools only when the corresponding backend is configured and the user's task calls for that evidence. Report an unavailable backend as unavailable, not as a clean signal.
- PostgreSQL replay, feedback, drift, and calibration are limited to the authenticated caller's own decisions. The server operator must configure a stable `CACHE_SCOPE_HMAC_KEY` with PostgreSQL so records remain available after restart.
- Configuration snapshots are redacted. Do not request `redact_secrets:false`; the server rejects unredacted snapshots.
- If a tool call returns `RATE_LIMIT_EXCEEDED`, treat it as temporary capacity pressure; retry later with bounded backoff rather than assuming the request is safe or sending a burst of retries.
- Incomplete or slow HTTP requests can receive HTTP 408, and new sockets can be closed when the server's connection cap is full. Treat either as an availability signal, not an allow verdict.
- On v0.1.2 and newer builds, WebSocket close code 1009 means a frame or fragmented message exceeded the configured request limit. Published v0.1.1 may instead close that connection without a close frame.

Record the returned request ID, verdict, confidence, and contributing signals. User-agent strings are self-declared, so a bot-name signal is a heuristic rather than proof of identity. TLS fingerprints supplied by an ordinary caller are unverified without the server's attestation path; never invent that provenance. The result supports a site owner's policy decision. A website must explicitly send requests to the classifier and enforce its own response; this skill cannot route live traffic or block a visitor by itself.
Sensitive-path checks account for common percent encoding and backslash spellings, including `/internal` and `/xmlrpc.php`, but a verdict does not replace the website's own URL normalization or authorization rules. Scanner user-agent signals (such as masscan, Nikto, sqlmap, and HttpClient) are heuristics because callers can spoof or omit that header.
