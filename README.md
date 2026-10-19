# request-guard-mcp

[![CI](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/License-GPLv3%2B-blue.svg)](LICENSE)

A **Rust MCP (Model Context Protocol) server** for request risk classification, enrichment, and abuse-signal analysis. The official MCP Inspector can call its tools over HTTP POST; custom WebSocket clients can use the JSON-RPC endpoint. Client support depends on transport and authentication compatibility. The `ai-scraping-defense` projects are optional clients. Stable release readiness is subject to the [adversarial release gate](docs/adversarial-release-gate.md).

The [companion skill](skills/request-guard-mcp/SKILL.md) tells a connected agent when and how to use this server’s classification tools. It does not deploy or replace the separate AI Scraping Defense products.

To package the skill for a directory listing, run `python3 scripts/package_skill.py`. The resulting local-only `dist/request-guard-mcp-skill.zip` contains only `request-guard-mcp/SKILL.md`; GitHub releases carry server binaries, not the skill ZIP. Install and configure the server separately. Verify the skill against a connected client before submitting a listing.

## Features

- **23 implemented MCP tool contracts** with truthful, backend-aware availability in `model_info`
- **WebSocket and HTTP POST transports** with JSON-RPC 2.0 protocol
- **Token-based authentication** (Bearer scheme) at connection establishment
- **Global concurrency control** via semaphore with backpressure
- **Per-tool timeouts** to prevent resource exhaustion
- **Prometheus metrics** at `/metrics` with p50/p95/p99 histograms
- **Two-level classification cache** (in-process Moka + shared Redis)
- **Structured JSON logging** via `tracing`
- **Redis-backed** threat reputation, canary registry, queue telemetry, and distributed cache
- **PostgreSQL-backed** decision replay, feedback, drift, and calibration reports with automatic schema setup
- **HMAC-attested JA3/JA4 rules** with known-bad sets, UA/TLS mismatch detection, and verified cache partitioning
- **MaxMind City/ASN/Anonymous-IP enrichment**, optionally combined with Redis reputation scores
- **Docker + Kubernetes** ready with HPA, NetworkPolicy, health probes

### Transport scope

WebSocket and HTTP POST JSON-RPC are the final supported MCP transports for
this server. A gRPC listener is intentionally out of scope because the project
does not define a separate protobuf service contract; the `grpc-tonic` feature
in `opentelemetry-otlp` is used only to export telemetry to an OTLP collector.

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

Each GitHub release includes a checksum-protected native bundle for Linux x64,
Windows x64, macOS Intel, and macOS Apple Silicon. Download the archive for your
platform, extract it, copy `.env.example` to `.env`, set `AUTH_TOKENS`, and run
`request-guard-mcp` (or `request-guard-mcp.exe` on Windows). A signed container
image is also published to `ghcr.io/rhamenator/request-guard-mcp`. Package the
companion skill locally with `python3 scripts/package_skill.py` if you need a
directory listing ZIP; GitHub releases do not include that ZIP.

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
