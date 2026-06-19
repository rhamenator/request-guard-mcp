# ai-scraping-defense-mcp

[![CI](https://github.com/rhamenator/ai-scraping-defense-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rhamenator/ai-scraping-defense-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-ready **Rust MCP (Model Context Protocol) server** providing AI-scraping defense capabilities to:
- [`rhamenator/ai-scraping-defense`](https://github.com/rhamenator/ai-scraping-defense) (Python/Django)
- [`rhamenator/ai-scraping-defense-iis`](https://github.com/rhamenator/ai-scraping-defense-iis) (.NET/IIS)

## Features

- **23 MCP tools**: classify, explain, batch_classify, health, model_info, feedback, enrich_ip/asn/ua, threat_lookup, canary_eval, abuse_pattern_match, drift_report, calibration_report, and more
- **WebSocket transport** with JSON-RPC 2.0 protocol
- **Token-based authentication** (****** scheme) at connection establishment
- **Global concurrency control** via semaphore with backpressure
- **Per-tool timeouts** to prevent resource exhaustion
- **Prometheus metrics** at `/metrics` with p50/p95/p99 histograms
- **In-process LRU cache** (Moka) for classify results
- **Structured JSON logging** via `tracing`
- **Optional integrations**: Redis, PostgreSQL, GeoIP (MaxMind MMDB)
- **Docker + Kubernetes** ready with HPA, NetworkPolicy, health probes

## Quickstart

```bash
# Clone and run
git clone https://github.com/rhamenator/ai-scraping-defense-mcp
cd ai-scraping-defense-mcp
cp .env.example .env
# Edit .env: set AUTH_TOKENS=your_strong_token
cargo run --release
```

Server starts on `http://0.0.0.0:8085`. Test it:

```bash
# Health check
curl http://localhost:8085/health

# WebSocket classify (requires wscat: npm install -g wscat)
wscat -H "Authorization: $(echo -n 'Bearer ')$YOUR_TOKEN" -c ws://localhost:8085/mcp
> {"jsonrpc":"2.0","id":1,"method":"classify","params":{"user_agent":"GPTBot/1.0","path":"/"}}
```

## Client Configuration

Add these variables to your client services:

```dotenv
MODEL_URI=mcp://primary/classify
MCP_SERVER_PRIMARY_TRANSPORT=ws
MCP_SERVER_PRIMARY_URL=ws://ai-scraping-defense-mcp:8085/mcp
MCP_SERVER_PRIMARY_AUTH_TOKEN=replace_me
MCP_SERVER_PRIMARY_TIMEOUT=10
```

See [docs/compatibility-matrix.md](docs/compatibility-matrix.md) for full details.

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
kubectl create secret generic mcp-secrets \
  --namespace ai-defense \
  --from-literal=auth_tokens=your_strong_token

make k8s-apply
```

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

MIT — see [LICENSE](LICENSE).
