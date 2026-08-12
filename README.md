# request-guard-mcp

[![CI](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rhamenator/request-guard-mcp/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/License-GPLv3%2B-blue.svg)](LICENSE)

A production-ready **Rust MCP (Model Context Protocol) server** for request risk classification, enrichment, and abuse-signal analysis. It can be used by any MCP-capable client over WebSocket or HTTP JSON-RPC; the `ai-scraping-defense` projects are supported clients, not required dependencies.

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
# Set AUTH_TOKENS=your_strong_token
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

## Ready-to-run releases

Each GitHub release includes a checksum-protected native bundle for Linux x64,
Windows x64, macOS Intel, and macOS Apple Silicon. Download the archive for your
platform, extract it, copy `.env.example` to `.env`, set `AUTH_TOKENS`, and run
`request-guard-mcp` (or `request-guard-mcp.exe` on Windows). A signed container
image is also published to `ghcr.io/rhamenator/request-guard-mcp`.

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
