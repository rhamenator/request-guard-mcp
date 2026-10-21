<p align="center">
  <img src="https://raw.githubusercontent.com/rhamenator/request-guard-mcp/main/.github/assets/logo.png" alt="Request Guard MCP logo" width="220">
</p>

# request-guard-mcp

[![CI](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/License-GPLv3%2B-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/request-guard-mcp.svg)](https://www.npmjs.com/package/request-guard-mcp)

A **Rust MCP (Model Context Protocol) server** for request risk classification, enrichment, and abuse-signal analysis. The official MCP Inspector can call its tools over HTTP POST; custom WebSocket clients can use the JSON-RPC endpoint. Client support depends on transport and authentication compatibility. The `ai-scraping-defense` projects are optional clients. Stable release readiness is subject to the [adversarial release gate](docs/adversarial-release-gate.md).

The experimental [v0.1.4 native release](https://github.com/rhamenator/request-guard-mcp/releases/tag/v0.1.4) includes checksum-protected binaries for Linux x64 (glibc and musl/Alpine), Windows x64, macOS Intel, and macOS Apple Silicon. The matching [npm package](https://www.npmjs.com/package/request-guard-mcp/v/0.1.4) passed a fresh public-registry install and MCP client test. Follow [INSTALL.md](INSTALL.md) for native setup or the [npm guide](docs/npm-release.md#install-and-connect) for npm setup.

The v0.1.4 release retains the Linux x64 musl archive for Alpine and passed [packaged PostgreSQL TLS qualification](docs/releases/v0.1.4-postgres-tls-evidence.md). Choose `linux-x64-musl` on Alpine and `linux-x64` on glibc hosts.

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
- **PostgreSQL TLS trust in v0.1.4** uses the host operating system's CA store. With `sslmode=verify-full`, a private database CA can instead be supplied through `sslrootcert` in `MCP__POSTGRES__URL`. In that verification mode, an untrusted issuer or hostname mismatch prevents startup when PostgreSQL is configured; `sslmode=require` encrypts without certificate verification.
- **HMAC-attested JA3/JA4 rules** with known-bad sets, UA/TLS mismatch detection, and verified cache partitioning
- **MaxMind City/ASN/Anonymous-IP enrichment**, optionally combined with Redis reputation scores
- **Docker + Kubernetes** ready with HPA, NetworkPolicy, health probes

### Transport scope

v0.1.4 supports authenticated HTTP POST JSON-RPC and a custom WebSocket
transport on `/mcp`. It does not offer stdio, SSE GET, OAuth discovery,
resources, or prompts. An authenticated ordinary GET to `/mcp` returns 405;
WebSocket upgrades remain available. The HTTP and custom WebSocket JSON-RPC
envelopes have [packaged-binary regression evidence](docs/releases/v0.1.4-ws-envelope-matrix.md)
for the supported flows. Optional streaming transports and a broader client
matrix are tracked in [issue #121](https://github.com/rhamenator/request-guard-mcp/issues/121).

Development main is preparing v0.1.5 with a process-local `--stdio` mode.
It uses newline-delimited JSON-RPC on stdin/stdout, sends diagnostics to
stderr, and does not open a listener. The launching user's process access is
the trust boundary; HTTP bearer tokens do not apply to stdio. This mode has
not yet passed packaged release qualification and is absent from v0.1.4.
PostgreSQL is currently excluded from this candidate mode because its
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

The v0.1.4 GitHub release includes checksum-protected native bundles for Linux x64 glibc and musl,
Windows x64, macOS Intel, and macOS Apple Silicon. Download the archive for your
platform and follow the bundled [INSTALL.md](INSTALL.md) for checksum verification,
token setup, startup, and MCP client connection. A container
image is also published to `ghcr.io/rhamenator/request-guard-mcp`. For a
long-running service deployment, use the container deployment examples. Package the
companion skill locally with `python3 scripts/package_skill.py` if you need a
directory listing ZIP; GitHub releases do not include that ZIP.

The [`request-guard-mcp` npm package](https://www.npmjs.com/package/request-guard-mcp)
is a separate native installation option. A fresh registry install of 0.1.4
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

The Kubernetes example pins the published v0.1.4 image and matching version
labels. The verified multiarch image index is
`sha256:a553eb4f25ee7eebdf67ad4d7df5be1c0d9b337e78274eb93565137134df90f7`.

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
