# Tool Contracts

All tools are called via JSON-RPC 2.0 over WebSocket or HTTP POST at `/mcp`, or over process-local stdio. The method name is the tool name (optionally prefixed with `tools/`).

## Core Tools

### `classify`
Classify a single HTTP request as bot/human.

**Request**
```json
{
  "ip": "1.2.3.4",
  "user_agent": "Mozilla/5.0 ...",
  "path": "/api/data",
  "method": "GET",
  "headers": { "accept": "application/json" },
  "tls_ja3": "72a589da586844d7f0818ce684948eea",
  "tls_ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
  "tls_fingerprint_source": "envoy",
  "tls_fingerprint_attestation": "v1:1700000000:<64 hex characters>",
  "request_id": "uuid-optional"
}
```

`tls_ja3`, `tls_ja4`, and `tls_fingerprint_source` remain untrusted without a
valid `tls_fingerprint_attestation`. The server consumes the token and derives
verification status itself; callers cannot assert `tls_fingerprint_verified`.
Only verified values affect TLS rules and cache identity. See
[TLS fingerprint attestation](tls-fingerprint-attestation.md).

Development main rejects unknown metadata names such as `pah` instead of
classifying a partial request as clean; put custom metadata in `extra`.
`tls_fingerprint_verified` is server-derived and rejected as caller input.
Empty or partial requests are still accepted. Published v0.1.5 can silently
ignore unknown names, so verify the input fields when using that release.
Existing PostgreSQL decision rows with the older serialized server-derived
TLS flag remain readable; the flag is ignored on replay and omitted from new
stored snapshots.

On development main, sensitive-path signals inspect bounded percent-decoded
route and file-name boundaries, excluding raw query and fragment text.
`/admin`, `/administrator`, `/prod.env`, and `/admin;jsessionid=1` remain
suspicious; `/products/configurable-shirt` and `/search?q=/admin` do not
receive a path-sensitive signal. Published v0.1.5 can still match sensitive
prefixes inside an ordinary path segment. Caller and origin URL normalization
can differ, so this signal is a heuristic rather than authorization or route
enforcement.

**Response**
```json
{
  "request_id": "uuid",
  "verdict": "block|flag|challenge|allow",
  "score": 0.92,
  "confidence": "high|medium|low|very_low",
  "threat_category": "ai_scraping|bot_traffic|scraping|...",
  "signals": [{ "name": "ua_ai_bot", "value": 1.0, "weight": 0.8, "description": "..." }],
  "latency_ms": 2,
  "model_version": "0.1.0"
}
```

### `explain`
Generate a human-readable explanation for a classification.

**Request**: `{ "classification": <ClassifyRequest or complete ClassifyResponse> }`. On development main, a supplied response is explained using its verdict, score and signals; it is caller-supplied and is not verified against a stored decision. Its score and verdict must agree with its bounded signals, whose descriptions remain unverified caller data. Request metadata is reclassified using the configured rules and TLS attestation without persisting a decision. Unknown request fields and incomplete response shapes are rejected. Published v0.1.5 can instead misread a response as an empty request; send the original request metadata to that release.

A batch result with `include_details: false` lacks its signal details and cannot be explained as a supplied response; pass original request metadata instead.
Responses produced by a different scoring version may also be rejected if their score or verdict differs from current rules; pass request metadata to recompute under this build.

**Response**: `{ "request_id", "explanation", "factors", "recommendations" }`

### `batch_classify`
Classify multiple requests in one call (max batch size configurable, default 50).

**Request**: `{ "items": [<ClassifyRequest>, ...], "options": { "fail_fast": false, "include_details": true } }`. The default maximum batch size is 50 and is configurable; an empty batch returns an empty result. On development main, `include_details: false` returns an empty `signals` array for each successful item. Omitting the option preserves the full result. Unknown batch, option and item field names reject the whole call during decoding, even with `fail_fast: false`; individual classification errors can still be returned per item. Published v0.1.5 accepts but ignores `include_details` and can silently ignore misspelled metadata.

**Response**: `{ "results": [{ "index", "result", "error" }], "total", "processed", "errors", "latency_ms" }`. With `fail_fast: false`, inspect `errors` and each item `error`: an item error has no classification result even though the batch call succeeds. With `fail_fast: true`, the call returns an error at the first failing item and no partial batch response.

### `health`
Server health check.

**Request**: none

**Response**: `{ "status": "healthy", "version", "uptime_seconds", "checks": {} }`. `uptime_seconds` is monotonic elapsed time since application state initialization, including time before the first health call.

### `model_info`
Return metadata about the server and available tools.

Each tool's `enabled` field reflects configured capability when server state
was initialized. It does not poll a backend or change when Redis or PostgreSQL
goes down later. Check `health` or `/ready` for current backend status.

**Response**: `{ "model_version", "tool_count", "tools": [...], "build_info": {} }`

### `feedback`
Submit a correction to a prior classification.

**Request**: `{ "request_id": "uuid", "correct_verdict": "allow", "notes": "..." }`

**Response**: `{ "accepted": true, "feedback_id": "uuid", "message": "..." }`

## Enrichment Tools

### `enrich_ip`
**Request**: `{ "ip": "1.2.3.4" }`
**Response**: `{ "ip", "country", "city", "asn", "org", "is_proxy", "is_datacenter", "is_tor", "risk_score" }`

On development main, IPv4-mapped IPv6 inputs use their IPv4 form for MaxMind
and Redis reputation lookup; `ip` echoes the parsed address in canonical spelling.
For valid noncanonical IPv6 input, development main checks the canonical Redis
key before the exact supplied spelling; it does not search other aliases.
IPv6 unique-local and link-local addresses, plus mapped private IPv4 addresses, receive the local/private
baseline without requiring an optional enrichment backend. This applies to
`enrich_ip`, not to the inbound `classify` verdict.

### `enrich_asn`
**Request**: `{ "asn": 15169 }`
**Response on development main**: `{ "asn", "organization", "country", "risk_score", "is_hosting", "asn_data_found", "reputation_listed" }`

`asn_data_found` means the configured MaxMind ASN index contained a record;
`reputation_listed` means Redis returned a threat record for the bare numeric ASN
key (for example `15169`, not `AS15169`). With neither source providing a record,
`risk_score: 0.1` is an unverified baseline, not a safe verdict. In Redis-only
mode, `organization: null` and `is_hosting: false` do not mean that an ASN was
checked for hosting. When ASN data is present, `is_hosting` is a coarse
organization-name substring heuristic, not a provider attestation. `country`
is currently always `null`. Published v0.1.5 has the older response without
the two evidence flags. This diagnostic does not change inbound `classify`.

### `enrich_ua`
**Request**: `{ "user_agent": "..." }`
**Response**: `{ "user_agent", "browser", "os", "device_type", "is_bot", "bot_name", "risk_score" }`
`is_bot` reports the user-agent parser's crawler category. On development main,
the diagnostic `risk_score` also reflects the rule engine's AI-bot and
scraper patterns, including some generic HTTP client strings; a scanner may
therefore have `is_bot: false` and a raised score. Broad substring patterns
can produce false positives. Published v0.1.5 may instead score those
scanners at 0.1. This hint is
not a safety verdict; use `classify` for an inbound request decision. User-agent
strings can be spoofed or omitted.

## Analytical Tools

### `score_breakdown`
Break down a diagnostic rule-engine score by contributing signal. Supply
`{"signals":{"user_agent":"GPTBot/1.0","path":"/"}}`, where `signals` is an
inbound classification request metadata object, not a raw list of signal
names, weights, or values. On development main, a supplied non-object,
unsupported key, or wrong field type returns `INVALID_REQUEST`; omitting the
optional `signals` field still returns an empty zero breakdown. Published
v0.1.5 may silently return zero for malformed supplied `signals`.
An unknown top-level argument, including a misspelling of `signals`, is also
rejected on development main.
This diagnostic does not reuse a stored decision or verify a caller-supplied
TLS fingerprint; use `classify` for the live verdict.

### `validate_payload`
Validate a payload against the schema for a named tool.
**Request**: `{ "tool": "classify", "payload": {...} }`
Development main also checks supported `feature_flags.flag` names and
`warmup.target` values. A valid result does not execute the tool, establish
that a feature is enabled, or test backend availability.

### `feature_flags`
List or get feature flags. **Request**: `{ "flag": "batch_classify" }` (omit for all).
Development main rejects unknown argument names and unsupported flag names;
published v0.1.5 may treat an unknown name as disabled. Values describe
startup configuration and backend presence, not live backend health. Use
`/ready` for live readiness; a disabled flag is not the same as an outage.

### `drift_report`
Statistical drift report over a time window.
**Request**: `{ "window_hours": 24 }`
**Response metrics** include real persisted `samples`, current-half score mean,
window standard deviation, verdict distribution, and per-signal frequency change.

### `calibration_report`
Precision/recall calibration report.
**Request**: `{ "window_hours": 24 }`
**Response** includes labelled `samples`, precision, recall, F1, false-positive
and false-negative rates computed from the latest feedback per decision.

### `queue_status`
Best-effort Redis tool-operation telemetry. With no `queue` argument, the
response lists names observed in Redis active-operation records. With a name,
the response includes that name even when Redis has no matching record;
zero activity does not establish that the queue exists or is healthy.
`depth` counts observed active-operation records, not waiting work; timed-out
records can remain active until Redis trim or expiry. `consumers`
is the configured global concurrency ceiling, not a live worker count or the
number of free permits. `rate_per_second` is completions in the last minute
divided by 60. Redis bookkeeping can lag or omit a record during outages;
these fields are not an audit trail or an ingress saturation signal.

### `config_snapshot`
Snapshot of current running configuration (secrets redacted by default).
**Request**: `{ "redact_secrets": true }`
Development main rejects unknown argument names. The `configured` fields
report configuration presence, not a live backend check; `features` are raw
configuration settings and may differ from effective `feature_flags` values.

### `self_test`
Run the built-in test suite.
**Request**: `{ "suite": "all" }`
The `suite` field may be omitted; `all` is the only supported value. An
unsupported suite is rejected instead of returning a passing result.

## Security Tools

### `threat_lookup`
**Request**: `{ "indicator": "1.2.3.4", "type": "ip" }`
`found:false` means no matching Redis record, not that an indicator is safe.
Always pass `type` for hash and ASN indicators; omitted `type` infers only IP,
lowercase-scheme URL, or domain.
Development main rejects unknown fields such as `typ`, lowercases domain names
and folds one trailing DNS dot, and rejects ambiguous domain spellings and
uppercase URL schemes. Domain indicators use ASCII letters, digits, dots,
hyphens and underscores; send internationalized domains as punycode. URL keys
remain exact strings: seed and query the same
lowercase-scheme spelling. Published v0.1.5 lacks these request checks.
For IP indicators on development main, the canonical Redis key takes priority,
then the exact supplied spelling is tried for a legacy record. Seed new IPv6
keys canonically; other valid aliases are not searched. Published v0.1.5 lacks
this legacy IPv6 fallback.
`validate_payload` checks the request shape, including unknown fields, but
does not pre-check the indicator's semantic spelling or Redis availability.

### `canary_eval`
**Request**: `{ "token": "canary-token-value" }`
To record optional caller context, use exactly `{"token":"canary-token-value","context":{"path":"/protected"}}`.
Development main rejects unknown top-level fields, including a misspelled
`context`; published v0.1.5 may silently ignore them. A matched context is
persisted unredacted in Redis subject to the configured event retention policy.

### `abuse_pattern_match`
**Request**: `{ "text": "...", "categories": ["injection", "ai_attack"] }`
`categories` is optional; an omitted or empty list checks all patterns. On
development main, accepted values are `injection`, `traversal`, `ai_attack`,
and `data_extraction` (ASCII case-insensitive, with surrounding whitespace
ignored); unknown values return an
invalid-request error. Development main checks SQL patterns across line breaks.
Published v0.1.5 may report a clean result for an unknown category or multiline
SQL. Results are heuristic signals, not a blocking decision.

## Operational Tools

### `warmup`
Run a best-effort synthetic classify or write a local cache marker. This does
not establish Redis health. Rule evaluation still occurs on a classification
cache hit, while scoring can be skipped. The `warmed` list means the warmup
call completed successfully, not that each component was exercised from a
cold start.
**Request**: `{ "target": "all|rule_engine|scorer|cache" }`
Development main rejects unknown argument names and unsupported targets;
published v0.1.5 can return an unknown target in `skipped`.

### `replay_decision`
Replay a prior decision deterministically.
**Request**: `{ "request_id": "uuid", "deterministic": true }`

### `redact_preview`
Preview redaction of sensitive fields.
**Request**: `{ "payload": {...}, "fields": ["authorization", "cookie"] }`
On development main, unknown request fields are rejected. Custom `fields` replace the defaults; the tool matches whole JSON keys and does not scan string values. Inspect the returned payload before sharing it.
