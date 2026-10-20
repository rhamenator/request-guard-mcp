# request-guard-mcp

[![CI](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/License-GPLv3%2B-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/request-guard-mcp.svg)](https://www.npmjs.com/package/request-guard-mcp)

A **Rust MCP (Model Context Protocol) server** for request risk classification, enrichment, and abuse-signal analysis. The official MCP Inspector can call its tools over HTTP POST; custom WebSocket clients can use the JSON-RPC endpoint. Client support depends on transport and authentication compatibility. The `ai-scraping-defense` projects are optional clients. Stable release readiness is subject to the [adversarial release gate](docs/adversarial-release-gate.md).

Install the experimental [npm release](https://www.npmjs.com/package/request-guard-mcp/v/0.1.3) with `npm install -g request-guard-mcp@0.1.3`, configure `AUTH_TOKENS`, then run `request-guard-mcp`. The package includes native binaries for Linux x64 (glibc and musl/Alpine), Windows x64, macOS Intel, and macOS Apple Silicon. Follow the [npm setup guide](docs/npm-release.md#install-and-connect) for environment and MCP client steps; [INSTALL.md](INSTALL.md) applies to downloaded native bundles.

The [v0.1.3 native release](https://github.com/rhamenator/request-guard-mcp/releases/tag/v0.1.3) adds a Linux x64 musl archive for Alpine. Choose `linux-x64-musl` on Alpine and `linux-x64` on glibc hosts. See the [Kali-to-Alpine qualification evidence](docs/alpine-qualification-v0.1.3-candidate.md) and its limits.

The [companion skill](skills/request-guard-mcp/SKILL.md) tells a connected agent when and how to use this server’s classification tools. It does not deploy or replace the separate AI Scraping Defense products.

To package the skill for a directory listing, run `python3 scripts/package_skill.py`. The resulting local-only `dist/request-guard-mcp-skill.zip` contains only `request-guard-mcp/SKILL.md`; GitHub releases carry server binaries, not the skill ZIP. Install and configure the server separately. Verify the skill against a connected client before submitting a listing.

## Features

- **23 implemented MCP tool contracts** with truthful, backend-aware availability in `model_info`
- **Path reconnaissance signals** inspect raw and up to four rounds of percent-encoded spellings, including `/internal` and `/xmlrpc.php`, without rewriting the original request or deciding origin routing
- **Scanner user-agent signals** recognize common tool names such as masscan, Nikto, sqlmap, and HttpClient as heuristics; a user agent is self-declared and never proves identity
- **WebSocket and HTTP POST transports** for implemented MCP methods; see the [current protocol limits](docs/inspector-interoperability.md#current-client-limits)
- **Token-based authentication** (Bearer scheme) before HTTP POST body buffering and at WebSocket connection establishment
- **Global concurrency control** with fail-fast tool rejection when capacity is full
- **HTTP header and body read deadlines**, a whole-connection cap, and per-tool execution timeouts; deploy proxy read and connection timeouts as an additional boundary
- **Prometheus metrics** at `/metrics` with p50/p95/p99 histograms
- **Two-level classification cache** (in-process Moka + shared Redis)
- **Structured JSON logging** via `tracing`
- **Redis-backed** threat reputation, canary registry, queue telemetry, and distributed cache
- **Caller-isolated PostgreSQL** decision replay, feedback, drift, and calibration reports with automatic schema setup; configure a stable `CACHE_SCOPE_HMAC_KEY` when PostgreSQL is enabled
- **HMAC-attested JA3/JA4 rules** with known-bad sets, UA/TLS mismatch detection, and verified cache partitioning
- **MaxMind City/ASN/Anonymous-IP enrichment**, optionally combined with Redis reputation scores
- **Docker + Kubernetes** ready with HPA, NetworkPolicy, health probes

### Transport scope

WebSocket and HTTP POST JSON-RPC are the final supported MCP transports for
this server. A gRPC listener is intentionally out of scope because the project
does not define a separate protobuf service contract; the `grpc-tonic` feature
in `opentelemetry-otlp` is used only to export telemetry to an OTLP collector.
Development main returns HTTP 405 for an authorized ordinary GET to `/mcp`
because it does not offer an SSE stream; a WebSocket upgrade on that path still
uses the custom WebSocket transport. Published v0.1.3 does not guarantee this
405 response.
Development main also requires any explicit `MCP-Protocol-Version` header on
a non-WebSocket `/mcp` HTTP request to equal `2025-06-18`, rejecting malformed or unsupported values with
HTTP 400 before reading a POST body. The header may be omitted for older
clients; this does not imply support for an older protocol revision. Published
v0.1.3 does not enforce the header. The custom WebSocket upgrade does not
use this Streamable HTTP header.
Development main returns HTTP 415 before reading an MCP POST body if an
explicit `Content-Type` is not `application/json` or
`application/json; charset=utf-8` (case-insensitive). A missing header remains
accepted for older direct clients. Published v0.1.3 does not enforce this
media-type policy. MCP 2025-06-18 clients should send
`Accept: application/json, text/event-stream`; this server returns JSON for
requests. Development main rejects an explicit `Accept` that rules out JSON
with HTTP 406 before reading the body, including `application/json;q=0` even
when a less specific wildcard allows other types. A missing `Accept` remains
accepted for older clients. Published v0.1.3 does not enforce this rule.
Use a JSON-RPC `2.0` envelope and a string or integer request ID. MCP
2025-06-18 forbids `null` request IDs. Development main returns JSON-RPC
`-32600` with an error ID of `null` for `null`, fractional, or otherwise
invalid request IDs on HTTP POST and WebSocket. Published v0.1.3 does not yet
enforce the `null` and fractional ID restriction.
Development main also rejects fractional client-response IDs and a `null`
success-response ID. A `null` error-response ID remains valid for parse or
invalid-request errors when the original request ID cannot be recovered;
published v0.1.3 does not enforce
the client-response ID restriction.
Development main also requires a client success-response `result` to be a JSON
object; primitive, `null`, and array results are rejected. Published v0.1.3 may
acknowledge those malformed responses.
Development main also requires `params` to be an object when present on a
request or notification; arrays and `null` receive JSON-RPC `-32600` on HTTP
POST requests and WebSocket messages. Omitted `params` remains valid. Published v0.1.3 may
accept array parameters on methods that do not inspect them.
On development main, an invalid ID-less notification or client response over
HTTP gets 400 with an empty body; an accepted one gets 202 with an empty body.
The custom WebSocket transport reports malformed messages as JSON-RPC errors.
v0.1.2 and newer builds return `-32600` for invalid envelope shapes and
`-32700` for malformed JSON. Client notifications receive no JSON-RPC response;
development main acknowledges accepted HTTP notifications and client responses
with 202 and an empty body. Published v0.1.3 uses 204 and an empty body.
Development main rejects MCP HTTP POST and WebSocket requests that carry an
`Origin` header unless that exact origin is in `MCP_ALLOWED_ORIGINS` (a
comma-separated list of full `http://` or `https://` origins). No origins are
allowed by default; non-browser clients that omit `Origin` still use the
configured authentication policy. For a browser client behind a reverse proxy, list its
trusted public origin explicitly. This server does not answer CORS preflights:
cross-origin browser clients also need a trusted proxy to handle CORS, while
same-origin browser traffic does not. Browser WebSocket APIs cannot set the
server's bearer Authorization header; a trusted proxy must authenticate the
browser and supply upstream credentials for that path. Use lowercase hosts and omit default
ports (`:80` for HTTP and `:443` for HTTPS) in the allowlist. The check applies
to the MCP endpoint, not `/health`, `/ready`, or `/metrics`; restrict those
endpoints at the proxy if browser access is a concern. The published v0.1.3 binary does not yet
enforce this Origin check; protect that release at the TLS proxy. An Origin
header is spoofable outside a browser and never replaces authentication.
v0.1.2 and newer builds send WebSocket close code 1009
when a frame or fragmented message exceeds `MCP__LIMITS__MAX_REQUEST_BYTES`.
The published v0.1.1 release can instead close the connection without a
WebSocket close frame.

## Quickstart

```bash
# Clone and run
git clone https://github.com/rhamenator/request-guard-mcp
cd request-guard-mcp
cp .env.example .env
# Prompt for strong application and backing-service credentials
python scripts/configure_credentials.py
cargo run --release
```

Server starts on `http://0.0.0.0:8085`. Test it:

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

## Client Configuration

Use these variables from any MCP-capable client that supports `MODEL_URI`-style provider routing:

```dotenv
MODEL_URI=mcp://primary/classify
MCP_SERVER_PRIMARY_TRANSPORT=ws
MCP_SERVER_PRIMARY_URL=ws://request-guard-mcp:8085/mcp
MCP_SERVER_PRIMARY_AUTH_TOKEN=replace_me
MCP_SERVER_PRIMARY_TIMEOUT=10
```

For clients already configured with the previous `ai-scraping-defense-mcp` hostname, Docker Compose and Kubernetes manifests include an optional legacy DNS alias/service that points to the same server.

See [docs/compatibility-matrix.md](docs/compatibility-matrix.md) for full details.
Trusted TLS producers must also follow [the attestation contract](docs/tls-fingerprint-attestation.md).

For a clean client check against an installed binary, run
`python3 scripts/inspector_smoke.py /path/to/request-guard-mcp`. It starts a
loopback instance with a temporary bearer token and uses pinned official MCP
Inspector 2.5.0 for `initialize`, `tools/list`, and `tools/call` (`classify` and
`explain`). Node.js 22.19.0 or newer, npm, and access to that Inspector package
are required.
See [the interoperability evidence](docs/inspector-interoperability.md) for
tested results and current protocol limits.

## Ready-to-run releases

The v0.1.3 GitHub release includes checksum-protected native bundles for Linux x64 glibc and musl,
Windows x64, macOS Intel, and macOS Apple Silicon. Download the archive for your
platform and follow the bundled [INSTALL.md](INSTALL.md) for checksum verification,
token setup, startup, and MCP client connection. A container
image is also published to `ghcr.io/rhamenator/request-guard-mcp`. For a
long-running service deployment, use the container deployment examples. Package the
companion skill locally with `python3 scripts/package_skill.py` if you need a
directory listing ZIP; GitHub releases do not include that ZIP.

The [`request-guard-mcp` npm package](https://www.npmjs.com/package/request-guard-mcp)
is a separate native installation option. A fresh registry install of 0.1.3
passed official MCP Inspector initialization, tool listing, `classify`, and
`explain`. See the [npm release guide](docs/npm-release.md) for package details.

## Docker

```bash
# Build and run
make docker-build
make docker-run

# With full stack (Redis, PostgreSQL, Prometheus, Grafana)
make docker-compose-up
```

## Kubernetes

```bash
# Create the namespace first, then copy secret.example.yaml, replace every
# placeholder with base64-encoded strong credentials, and apply the copy.
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/secret.yaml

make k8s-apply
```

The application, Redis, and PostgreSQL intentionally refuse to start with the
example credentials. Do not commit `deploy/k8s/secret.yaml`.

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
| `batch_classify` | Classify multiple requests |
| `health` | Server health check |
| `model_info` | Server and tool metadata |
| `feedback` | Submit classification feedback |
| `score_breakdown` | Detailed score breakdown |
| `validate_payload` | Validate a tool payload |
| `feature_flags` | List feature flags |
| `warmup` | Warm up caches |
| `replay_decision` | Replay a past decision |
| `redact_preview` | Preview field redaction |
| `enrich_ip` | IP geolocation/ASN enrichment |
| `enrich_asn` | ASN organization enrichment |
| `enrich_ua` | User-agent parsing |
| `threat_lookup` | Threat indicator lookup |
| `canary_eval` | Canary token evaluation |
| `abuse_pattern_match` | Abuse pattern detection |
| `drift_report` | Score drift over time |
| `calibration_report` | Precision/recall report |
| `queue_status` | Processing queue status |
| `config_snapshot` | Running config snapshot |
| `self_test` | Built-in test suite |

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
