<p align="center">
  <img src="https://raw.githubusercontent.com/rhamenator/request-guard-mcp/main/.github/assets/logo.png" alt="Request Guard MCP logo" width="220">
</p>

# request-guard-mcp

[![CI](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/License-GPLv3%2B-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/request-guard-mcp.svg)](https://www.npmjs.com/package/request-guard-mcp)

A **Rust MCP (Model Context Protocol) server** for request risk classification, enrichment, and abuse-signal analysis. The official MCP Inspector can call its tools over HTTP POST; custom WebSocket clients can use the JSON-RPC endpoint. Client support depends on transport and authentication compatibility. The `ai-scraping-defense` projects are optional clients. Stable release readiness is subject to the [adversarial release gate](docs/adversarial-release-gate.md).

The experimental [v0.1.5 native release](https://github.com/rhamenator/request-guard-mcp/releases/tag/v0.1.5) includes checksum-protected binaries for Linux x64 (glibc and musl/Alpine), Windows x64, macOS Intel, and macOS Apple Silicon. Follow the [v0.1.5 INSTALL.md](https://github.com/rhamenator/request-guard-mcp/blob/v0.1.5/INSTALL.md) for that release's native setup; the main-branch instructions describe later development changes. The matching [npm package](https://www.npmjs.com/package/request-guard-mcp/v/0.1.5) is also published; see the [npm guide](docs/npm-release.md#install-and-connect). v0.1.4 does not contain stdio.

The v0.1.5 release retains the Linux x64 musl archive for Alpine and the [PostgreSQL TLS behavior qualified for v0.1.4](docs/releases/v0.1.4-postgres-tls-evidence.md). Choose `linux-x64-musl` on Alpine and `linux-x64` on glibc hosts.

The [companion skill](skills/request-guard-mcp/SKILL.md) tells a connected agent when and how to use this server’s classification tools. It does not deploy or replace the separate AI Scraping Defense products.

To package the skill for a directory listing, run `python3 scripts/package_skill.py`. The resulting local-only `dist/request-guard-mcp-skill.zip` contains only `request-guard-mcp/SKILL.md`; GitHub releases carry server binaries, not the skill ZIP. Install and configure the server separately. Verify the skill against a connected client before submitting a listing.

## Features

- **23 implemented MCP tool contracts** with truthful, backend-aware availability in `model_info`
- **Path reconnaissance signals** inspect raw and up to four rounds of percent-encoded spellings, including `/internal` and `/xmlrpc.php`, without rewriting the original request or deciding origin routing
- **Scanner user-agent signals** recognize common tool names such as masscan, Nikto, sqlmap, and HttpClient as heuristics; a user agent is self-declared and never proves identity
- **WebSocket and HTTP POST transports** for implemented MCP methods; see the [current protocol limits](docs/inspector-interoperability.md#current-client-limits)
- **Token-based authentication** (Bearer scheme) before HTTP POST body buffering and at WebSocket connection establishment
- Development main bounds JSON structural complexity before parsing, in addition to the 1 MiB default body limit, to reject unusually wide arrays/objects (HTTP 413; JSON-RPC `-413` on WebSocket/stdio). Published v0.1.5 has only the byte limit.
- **Global concurrency control** with fail-fast tool rejection when capacity is full
- **HTTP/1 header and body read deadlines**, a whole-connection cap, and per-tool execution timeouts; development main stops admitting non-upgraded HTTP/1 requests at about 120 seconds after the first request, gives in-flight responses a bounded drain, and closes an HTTP/1 keep-alive connection after 128 requests. A non-reading peer can still lose its response at the drain deadline. It bounds HTTP/2 setup, idle time (default 60 seconds), connection age (120 seconds), and requests per connection (128). WebSocket upgrades use separate limits. Published v0.1.5 lacks these HTTP/1 age/request and HTTP/2 protections. An active peer can reconnect, so deploy proxy read, connection, and rate limits as an additional boundary
- On development main, SIGTERM or Ctrl-C stops network admission, rejects newly dispatched HTTP requests on existing connections, and waits up to the HTTP body deadline plus the larger tool/classify deadline plus two seconds for active HTTP connections before closing stragglers and flushing telemetry. Idle HTTP connections are asked to close immediately; silent preface sockets have no active response and are dropped. A second signal forces immediate exit. Existing WebSocket sessions are closed when the process exits; clients must reconnect to another instance. At default limits, allow at least 75 seconds of orchestrator stop grace (`docker stop -t 75`, or the equivalent deployment setting); increase that grace if you raise the body or tool deadlines. Compose sets 75 seconds for its local source build. Published v0.1.5 exits on SIGTERM without this drain.
- [Ingress fairness boundary and bounded proxy probe](docs/ingress-proxy-limits.md) explain how to qualify that external limit without treating per-connection server caps as client fairness.
- **Prometheus metrics** at `/metrics` with p50/p95/p99 histograms
- **Two-level classification cache** (in-process Moka + shared Redis)
- On development main, classification cache keys also include the recorded source commit, version, cache schema marker, and normalized known-bad TLS fingerprint sets. Release builds from clean checkouts and deployments with different TLS threat sets do not reuse an earlier distributed verdict. This partition covers those inputs only; assess any future verdict-affecting configuration separately. Locally built binaries, including builds with `unknown` commit metadata or uncommitted source changes, rely on the explicit cache schema marker; after changing classification source locally, use a new Redis key prefix or clear old cache entries. Published v0.1.5 lacks this partition: a v0.1.5 replica can keep serving its cached verdict during a rolling upgrade or after a threat-set change until the configured TTL expires (300 seconds by default). A patched build does not read those old keys.
- **Structured diagnostic logging** via `tracing`; no per-invocation audit trail
- **Redis-backed** threat reputation, canary registry, queue telemetry, and distributed cache
- **Redis transport limit:** v0.1.5 and development main support plaintext `redis://` only. `rediss://` fails startup; no TLS downgrade occurs. Use Redis only on a trusted, isolated local/private link, or terminate an independently secured tunnel at a loopback endpoint accessible only to trusted local processes. Do not send a Redis password over an untrusted network or publish the demo Redis service externally. Disable the optional Redis integration when that boundary is unavailable. The included Compose and Kubernetes backend URLs are local demo examples, not evidence of encrypted Redis transport.
- **Redis canary retention in v0.1.5 and development main:** the canary registry and the most recent 10,000 canary events have no automatic time-based expiry. When caller context encodes to at most 4096 bytes, a matched `canary_eval` stores that JSON value unredacted in a shared Redis event, without PostgreSQL's per-caller scope. Keep secrets and unnecessary personal data out of that context; operators must set a retention/purge schedule for these keys and their Redis persistence, replicas, and backups. See the [runbook](docs/runbook.md#loading-reputation-and-canary-data). The Redis cache and queue TTLs do not govern canary records.
- Development main bounds best-effort Redis tool-operation bookkeeping to 500 ms before and after dispatch, so a stalled optional Redis connection does not hold a core response on those records. Timed-out records may temporarily be absent or remain active in `queue_status` until Redis trim/expiry. Published v0.1.5 lacks this bound; Redis-dependent tools still require a healthy backend.
- **Caller-isolated PostgreSQL** decision replay, feedback, drift, and calibration reports with automatic schema setup; configure a stable `CACHE_SCOPE_HMAC_KEY` when PostgreSQL is enabled
- On development main, startup skips table DDL when the PostgreSQL schema is already current. First install or legacy-schema migration still takes DDL locks and should be scheduled during a quiet write window. Published v0.1.5 does not use this startup fast path.
- **Feedback on development main:** reusing a caller-scoped `request_id` replaces its persisted decision. If the stored replay inputs or response change, prior feedback is cleared; an equivalent retry keeps it. Submit new feedback for a changed decision. Published v0.1.5 does not clear old feedback on replacement; use a fresh request ID for each distinct event. Existing stale labels from older releases are not repaired automatically.
- **PostgreSQL data minimization on development main:** replay request JSON retains a subset of current rule inputs (user agent, path, method, and presence of Accept/Accept-Language headers). Header values, body snippets, arbitrary `extra`, IP, referrer, timestamp, request ID and TLS attestation material are omitted from that request JSON; the stored response still contains the request ID, verdict and signals. Paths and user agents can still contain personal data. Operators must set and execute a retention policy; existing rows from v0.1.5 are not rewritten automatically. Replay of an attested TLS fingerprint cannot reproduce its expired trusted provenance. Published v0.1.5 persists the full classification request instead.
- **PostgreSQL TLS trust in v0.1.4** uses the host operating system's CA store. With `sslmode=verify-full`, a private database CA can instead be supplied through `sslrootcert` in `MCP__POSTGRES__URL`. In that verification mode, an untrusted issuer or hostname mismatch prevents startup when PostgreSQL is configured; `sslmode=require` encrypts without certificate verification.
- **HMAC-attested JA3/JA4 rules** with known-bad sets, UA/TLS mismatch detection, and verified cache partitioning
- **MaxMind City/ASN/Anonymous-IP enrichment**, optionally combined with Redis reputation scores
- **Docker + Kubernetes** ready with HPA, NetworkPolicy, health probes

### Transport scope

v0.1.5 supports authenticated HTTP POST JSON-RPC and a custom WebSocket
transport on `/mcp`, plus process-local stdio. It does not offer SSE GET, OAuth discovery,
resources, or prompts. An authenticated ordinary GET to `/mcp` returns 405;
WebSocket upgrades remain available. The HTTP and custom WebSocket JSON-RPC
envelopes have [packaged-binary regression evidence](docs/releases/v0.1.4-ws-envelope-matrix.md)
for the supported flows. Optional streaming transports and a broader client
matrix are tracked in [issue #121](https://github.com/rhamenator/request-guard-mcp/issues/121).
Development main serves custom WebSocket over HTTP/1 upgrade and does not
enable HTTP/2 extended CONNECT.
Development main also limits each WebSocket response or control-frame send to
five seconds so a non-reading client cannot retain a connection permit during
an unbounded write. Published v0.1.5 lacks that send deadline.
When two or more distinct bearer tokens are configured on development main,
one bearer can hold at most `max_connections - 1` concurrent WebSocket slots
(or one slot if the global cap is one). With at least two global slots, a
second bearer can therefore connect when one bearer keeps sending Ping frames.
This does not allocate a guaranteed
slot to every bearer or protect against several cooperating tokens, reconnect
floods, or distributed load. A same-bearer upgrade over that cap receives HTTP
503 and may retry with bounded backoff. Single-token deployments retain the
configured global WebSocket cap. Published v0.1.5 has no per-bearer cap.

Run the native executable with `--stdio` for a local process MCP client. It
uses newline-delimited JSON-RPC on stdin/stdout, sends diagnostics to
stderr, and does not open a listener. The launching user's process access is
the trust boundary; HTTP bearer tokens do not apply to stdio. This mode passed
private five-platform packaged smoke, official Python SDK 2.3.0 and clean
npm-installed launcher tests before release. See the
[candidate evidence](docs/releases/v0.1.5-stdio-candidate.md). It is absent
from v0.1.4. PostgreSQL is excluded from stdio because its
persistent per-caller rows have no expiry; see [setup and limits](INSTALL.md).

For HTTP POST, send `Content-Type: application/json` and
`Accept: application/json, text/event-stream`. An explicit unsupported
content type gets 415; an explicit `Accept` that excludes JSON gets 406.
After initialization, send `MCP-Protocol-Version: 2025-06-18`; an explicit
malformed, duplicate, or unsupported value gets 400. Missing versions and
media headers remain accepted for older direct clients. The server sends JSON
for requests and does not offer an SSE response stream. Accepted client
notifications and responses get 202 with no body.

Use JSON-RPC `2.0` envelopes with string or integer request IDs. `null` and
fractional request IDs receive `-32600`; valid IDs are echoed for invalid
`params`. Request and notification `params`, when present, must be objects.
Client success responses require a JSON object `result` and a string or
integer ID. A `null` error-response ID is accepted only for parse or
invalid-request errors when the original ID cannot be recovered. Rejected
ID-less HTTP notifications or client responses get 400 with no body.
The custom WebSocket transport reports malformed messages as JSON-RPC errors.

HTTP POST and WebSocket requests carrying `Origin` require an exact entry in
`MCP_ALLOWED_ORIGINS`; the default empty allowlist denies such requests.
Non-browser clients without `Origin` remain subject to bearer authentication.
The server does not handle CORS preflights, so cross-origin browser clients
need a trusted proxy. Browser WebSocket clients also need that proxy to
authenticate them and set an upstream bearer header. Origin is spoofable
outside browsers and never replaces authentication. The check does not cover
`/health`, `/ready`, or `/metrics`; restrict those endpoints at the proxy.

v0.1.2 and newer builds send WebSocket close code 1009 for an oversized frame
or fragmented message; v0.1.1 may instead close without a close frame.
The earlier v0.1.3 release predates the v0.1.4 HTTP and Origin rules above;
use its [tagged documentation](https://github.com/rhamenator/request-guard-mcp/tree/v0.1.3)
when operating that version.

## Quickstart (Linux/macOS)

For Windows, follow the native bundle's `INSTALL.md` or create `.env` in an
NTFS directory restricted to the server account and authorized administrators.
Verify its ACL with `icacls .env` before running the credential helper; the
helper requires explicit confirmation because it cannot enforce Windows ACLs.

```bash
# Clone and run
git clone https://github.com/rhamenator/request-guard-mcp
cd request-guard-mcp
(umask 077; cp .env.example .env)
# Its default binds all interfaces for container deployments; do not run the
# local quickstart without the loopback override below.
# Prompt for strong application and backing-service credentials; the helper
# restricts .env to mode 0600 on Linux/macOS before writing secrets.
python scripts/configure_credentials.py
# The shell value overrides .env and keeps unauthenticated endpoints local.
MCP__HOST=127.0.0.1 cargo run --release
```

Server starts on `http://127.0.0.1:8085`. Test it:

```bash
# Health check
curl http://localhost:8085/health

# HTTP JSON-RPC classify
curl -H "Authorization: Bearer $YOUR_TOKEN" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  --data '{"jsonrpc":"2.0","id":1,"method":"classify","params":{"user_agent":"GPTBot/1.0","path":"/"}}' \
  http://localhost:8085/mcp

# WebSocket classify (requires wscat: npm install -g wscat)
wscat -H "Authorization: $(echo -n 'Bearer ')$YOUR_TOKEN" -c ws://localhost:8085/mcp
> {"jsonrpc":"2.0","id":1,"method":"classify","params":{"user_agent":"GPTBot/1.0","path":"/"}}
```

Development main bounds concurrent Redis and PostgreSQL pings on the
unauthenticated `/health` and `/ready` endpoints to one second per request.
A stalled backend makes `/health` return HTTP 200 with `"status":"unhealthy"`
in its JSON body and `/ready` return HTTP 503. Published v0.1.5 lacks this
explicit handler deadline. Restrict these endpoints at the proxy.

## Client Configuration

For optional `ai-scraping-defense` clients that support `MODEL_URI`-style provider routing, use these client-specific variables:

```dotenv
MODEL_URI=mcp://primary/classify
MCP_SERVER_PRIMARY_TRANSPORT=ws
MCP_SERVER_PRIMARY_URL=ws://request-guard-mcp:8085/mcp
MCP_SERVER_PRIMARY_AUTH_TOKEN=replace_me
MCP_SERVER_PRIMARY_TIMEOUT=10
```

The `ws://request-guard-mcp:8085` example sends the bearer token without
transport encryption and is only suitable on a trusted private network. Use
`wss://` through a trusted TLS-terminating proxy outside that boundary. Block
unauthenticated `/health`, `/ready`, and `/metrics` at the proxy or firewall,
or allow only trusted monitoring sources.

For clients already configured with the previous `ai-scraping-defense-mcp` hostname, Docker Compose and Kubernetes manifests include an optional legacy DNS alias/service that points to the same server.

Other MCP clients should use HTTP POST, or stdio with v0.1.5 and later, rather than assume these provider-routing variables are understood. WebSocket is for compatible custom JSON-RPC clients. See [docs/compatibility-matrix.md](docs/compatibility-matrix.md) for tested clients and transport limits.
Trusted TLS producers must also follow [the attestation contract](docs/tls-fingerprint-attestation.md).

For a clean client check against an installed binary, run
`python3 scripts/inspector_smoke.py /path/to/request-guard-mcp`. It starts a
loopback instance with a temporary bearer token and uses pinned official MCP
Inspector 2.11.0 for `initialize`, `tools/list`, and `tools/call` (`classify` and
`explain`). Node.js 22.19.0 or newer, npm, and access to that Inspector package
are required.
Published v0.1.5 release jobs used the earlier Inspector 2.5.0 pin; the
2.11.0 smoke has also passed against its exact public Linux x64 binary.
See [the interoperability evidence](docs/inspector-interoperability.md) for
tested results and current protocol limits.

## Ready-to-run releases

The v0.1.5 GitHub release includes checksum-protected native bundles for Linux x64 glibc and musl,
Windows x64, macOS Intel, and macOS Apple Silicon. Download the archive for your
platform and follow its bundled INSTALL.md for checksum verification,
token setup, startup, and MCP client connection. A container
image is also published to `ghcr.io/rhamenator/request-guard-mcp`. For a
long-running service deployment, use the container deployment examples. Package the
companion skill locally with `python3 scripts/package_skill.py` if you need a
directory listing ZIP; GitHub releases do not include that ZIP.
Keep request IDs nonsecret: published v0.1.5 can include a caller-supplied ID
in tool-error warnings. Development main logs categorical tool error codes.

The [`request-guard-mcp` npm package](https://www.npmjs.com/package/request-guard-mcp)
is a separate native installation option. A fresh registry install of 0.1.5
passed official MCP Inspector initialization, tool listing, `classify`, and
`explain`, plus the bounded stdio smoke on Linux x64. v0.1.4 has no stdio. See the
[npm release guide](docs/npm-release.md).
For HTTP mode with the published v0.1.5 npm launcher, a forced kill of only
the Node wrapper can leave its native listener running; stop the child or
process group too. Development HTTP launchers use a private parent pipe so
the native server can start a bounded drain when its wrapper disappears.
Forced-kill cleanup on macOS and Windows is being qualified on packaged builds.

## Docker

```bash
# Build and run
make docker-build
make docker-run

# Local demo stack (Redis, PostgreSQL, Prometheus, Grafana)
python scripts/configure_credentials.py
make docker-compose-up
```

The Compose example builds development main, uses private generated `.env`
credentials, and binds the MCP, Prometheus, and Grafana host ports to
`127.0.0.1` only. Prometheus scrapes the MCP `/metrics` endpoint within the
Compose network; Grafana at `http://127.0.0.1:3000` has Prometheus provisioned
as its default datasource (user `admin`, password from `GRAFANA_ADMIN_PASSWORD`
in `.env`). The monitoring images are pinned to reviewed version digests; update
them deliberately. `/metrics` is unauthenticated inside this local demo network.
The backend links in this example are plaintext and are not a production
networking or secrets-management design. See the [runbook](docs/runbook.md).

## Kubernetes

```bash
# Create the namespace first, then copy secret.example.yaml, replace every
# placeholder with base64-encoded strong credentials, and apply the copy.
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/secret.yaml

make k8s-apply
```

The Kubernetes example pins the historical published v0.1.4 image and matching
version labels. It does not include v0.1.5 changes. For a newer release, review
and update the image digest, version labels, configuration, and instructions as
one deployment change. The verified v0.1.4 multiarch image index is
`sha256:a553eb4f25ee7eebdf67ad4d7df5be1c0d9b337e78274eb93565137134df90f7`.

Replace **every** example Secret value before deployment. Development main
rejects the shipped bearer, cache-scope HMAC, and TLS attestation key
placeholders at server startup; published v0.1.5 does not reject the latter
two. Configured TLS attestation keys are also validated in stdio mode. Redis
and PostgreSQL may start with example passwords, so do not rely on
their startup checks to protect the deployment. Do not commit
`deploy/k8s/secret.yaml`.

## Development

Stable releases also require the [adversarial release gate](docs/adversarial-release-gate.md) against the packaged server in an authorized lab.

```bash
make test        # Run all tests
make fmt         # Format code
make clippy      # Run linter
make audit       # Security audit
make ci          # All CI checks
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for a full system diagram and component overview.

## Tools

| Tool | Description |
|------|-------------|
| `classify` | Classify a request as bot/human |
| `explain` | Explain a classification decision |
| `batch_classify` | Classify multiple requests. On development main, `options.include_details: false` omits per-item signal details; omitted or `true` preserves the full result. Check `errors` and each item error when `fail_fast` is false. Published v0.1.5 accepts but ignores `include_details`. |
| `health` | Server health check |
| `model_info` | Server and tool metadata |
| `feedback` | Submit classification feedback |
| `score_breakdown` | Diagnostic rule-engine score for optional `signals` containing an inbound classification request metadata object, such as `{"user_agent":"GPTBot/1.0","path":"/"}`. Development main rejects an unknown field, raw signal list, or wrong field type instead of reporting a clean zero; published v0.1.5 can return zero for malformed supplied `signals`. This diagnostic is not a persisted verdict and does not verify a caller-supplied TLS fingerprint. |
| `validate_payload` | Check a named tool's payload against its request shape; development main also checks supported `feature_flags.flag` and `warmup.target` names. Errors use root path `/`. Execution, feature enablement, backend availability and other business rules are not checked. |
| `feature_flags` | List startup feature flags; development main rejects unknown flag names; use `/ready` for live backend readiness. |
| `warmup` | Best-effort synthetic classify/local-cache warmup, not a Redis health check; development main rejects unsupported targets. |
| `replay_decision` | Replay a past decision |
| `redact_preview` | Preview case-insensitive, exact JSON key redaction. Development main lists only keys actually replaced in `fields_redacted` and rejects misspelled request fields; published v0.1.5 can misreport this list. Custom `fields` replace the defaults; text inside string values is not parsed. |
| `enrich_ip` | IP geolocation/ASN enrichment; development main looks up IPv4-mapped IPv6 under its IPv4 key and treats IPv6 unique-local/link-local as local addresses. Published v0.1.5 does not include this correction. |
| `enrich_asn` | ASN organization enrichment |
| `enrich_ua` | User-agent parsing and a diagnostic risk hint. Development main also raises the score for rule-engine AI-bot and scraper patterns such as sqlmap, Nikto, masscan and generic HTTP client strings; published v0.1.5 can report 0.1 for them. Broad pattern matches can be false positives. `is_bot` reflects the parser's crawler category, so `false` or a low score is not a safe verdict. Use `classify` for inbound decisions. |
| `threat_lookup` | Exact Redis threat-record lookup, not a safety verdict. Development main rejects unknown arguments, folds one trailing domain dot and domain case, rejects uppercase URL schemes, and checks the canonical IP key before the exact supplied spelling for legacy IPv6 records. Seed new IPv6 keys canonically; other aliases are not searched. URL keys otherwise match exact strings. Published v0.1.5 lacks these corrections. |
| `canary_eval` | Canary token evaluation. Development main rejects unknown arguments such as a misspelled `context`; published v0.1.5 may silently omit that context. Matched context is stored in Redis unredacted. |
| `abuse_pattern_match` | Heuristic abuse pattern detection. Development main accepts the optional categories `injection`, `traversal`, `ai_attack`, `data_extraction` without regard to ASCII case and rejects unknown categories; published v0.1.5 can return a false-clean result for an unknown category or multiline SQL text. This tool does not enforce a blocking policy. |
| `drift_report` | Score drift over time |
| `calibration_report` | Precision/recall report |
| `queue_status` | Best-effort Redis tool-operation telemetry, not a backlog. `depth` counts observed active records, which can lag or remain stale; `consumers` is the configured global concurrency ceiling, not live workers or free permits. A requested name with no records returns zero activity, which does not prove the queue exists or is healthy. Published v0.1.5 advertises this tool as queue status but uses the same field semantics. |
| `config_snapshot` | Running config snapshot |
| `self_test` | Built-in test suite (`suite: "all"` or omitted) |

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
