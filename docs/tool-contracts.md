# Tool Contracts

All tools are called via JSON-RPC 2.0 over WebSocket. The method name is the tool name (optionally prefixed with `tools/`).

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
  "request_id": "uuid-optional"
}
```

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

**Request**: `{ "classification": <ClassifyRequest or ClassifyResponse> }`

**Response**: `{ "request_id", "explanation", "factors", "recommendations" }`

### `batch_classify`
Classify multiple requests in one call (max batch size configurable, default 50).

**Request**: `{ "items": [<ClassifyRequest>, ...], "options": { "fail_fast": false } }`

**Response**: `{ "results": [{ "index", "result", "error" }], "total", "processed", "errors", "latency_ms" }`

### `health`
Server health check.

**Request**: none

**Response**: `{ "status": "healthy", "version", "uptime_seconds", "checks": {} }`

### `model_info`
Return metadata about the server and available tools.

**Response**: `{ "model_version", "tool_count", "tools": [...], "build_info": {} }`

### `feedback`
Submit a correction to a prior classification.

**Request**: `{ "request_id": "uuid", "correct_verdict": "allow", "notes": "..." }`

**Response**: `{ "accepted": true, "feedback_id": "uuid", "message": "..." }`

## Enrichment Tools

### `enrich_ip`
**Request**: `{ "ip": "1.2.3.4" }`
**Response**: `{ "ip", "country", "city", "asn", "org", "is_proxy", "is_datacenter", "is_tor", "risk_score" }`

### `enrich_asn`
**Request**: `{ "asn": 15169 }`
**Response**: `{ "asn", "organization", "country", "risk_score", "is_hosting" }`

### `enrich_ua`
**Request**: `{ "user_agent": "..." }`
**Response**: `{ "user_agent", "browser", "os", "device_type", "is_bot", "bot_name", "risk_score" }`

## Analytical Tools

### `score_breakdown`
Break down a score by contributing engine/signal.

### `validate_payload`
Validate a payload against the schema for a named tool.
**Request**: `{ "tool": "classify", "payload": {...} }`

### `feature_flags`
List or get feature flags. **Request**: `{ "flag": "batch_classify" }` (omit for all).

### `drift_report`
Statistical drift report over a time window.
**Request**: `{ "window_hours": 24 }`

### `calibration_report`
Precision/recall calibration report.
**Request**: `{ "window_hours": 24 }`

### `queue_status`
Status of processing queues.

### `config_snapshot`
Snapshot of current running configuration (secrets redacted by default).
**Request**: `{ "redact_secrets": true }`

### `self_test`
Run the built-in test suite.
**Request**: `{ "suite": "all" }`

## Security Tools

### `threat_lookup`
**Request**: `{ "indicator": "1.2.3.4", "type": "ip" }`

### `canary_eval`
**Request**: `{ "token": "canary-token-value" }`

### `abuse_pattern_match`
**Request**: `{ "text": "...", "categories": ["injection", "ai_attack"] }`

## Operational Tools

### `warmup`
Warm up caches and engines.
**Request**: `{ "target": "all|rule_engine|scorer|cache" }`

### `replay_decision`
Replay a prior decision deterministically.
**Request**: `{ "request_id": "uuid", "deterministic": true }`

### `redact_preview`
Preview redaction of sensitive fields.
**Request**: `{ "payload": {...}, "fields": ["authorization", "cookie"] }`
