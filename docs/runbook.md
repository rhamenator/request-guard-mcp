# Runbook

## Starting the Server

### Local (Cargo)
```bash
cp .env.example .env
# Edit .env: set AUTH_TOKENS to a strong value
source .env
cargo run --release
```

### Docker
```bash
docker run --rm \
  -p 8085:8085 \
  -e AUTH_TOKENS=your_strong_token \
  -e LOG_LEVEL=info \
  ghcr.io/rhamenator/request-guard-mcp:latest
```

### Docker Compose (with Redis + PostgreSQL)
```bash
cd docker
AUTH_TOKENS=your_token \
REDIS_PASSWORD=your_url_safe_redis_password \
POSTGRES_PASSWORD=your_url_safe_postgres_password \
GRAFANA_ADMIN_PASSWORD=your_grafana_password \
docker compose up -d
```

For this Compose shorthand, use strong URL-safe passwords containing only URI
unreserved characters. Redis and
PostgreSQL data are stored in named volumes. The MCP server creates its
PostgreSQL tables and indexes idempotently at startup.

### Kubernetes
```bash
# Create the namespace first
kubectl apply -f deploy/k8s/namespace.yaml

# Create consistent backend/application secrets. This example uses URL-safe passwords.
kubectl create secret generic mcp-secrets \
  --namespace request-guard \
  --from-literal=auth_tokens=your_strong_token \
  --from-literal=redis_password=your_redis_password \
  --from-literal=redis_url='redis://:your_redis_password@redis:6379' \
  --from-literal=postgres_password=your_postgres_password \
  --from-literal=postgres_url='postgresql://mcp:your_postgres_password@postgres:5432/mcp'

# Apply manifests
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/backends.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/hpa.yaml
kubectl apply -f deploy/k8s/networkpolicy.yaml
```

The backend StatefulSets request 1 GiB for Redis and 5 GiB for PostgreSQL.
Adjust their storage class/size for production, or omit `backends.yaml` and
point the secret URLs at managed services.

### MaxMind databases

Set any combination of these variables to readable MMDB files:

```dotenv
MCP__GEOIP__CITY_MMDB_PATH=/data/geoip/GeoIP2-City.mmdb
MCP__GEOIP__ASN_MMDB_PATH=/data/geoip/GeoLite2-ASN.mmdb
MCP__GEOIP__ANONYMOUS_IP_MMDB_PATH=/data/geoip/GeoIP2-Anonymous-IP.mmdb
```

For Kubernetes, provision a `geoip-mmdb` PVC containing those licensed files,
then apply `deploy/k8s/geoip-patch.example.yaml` as a strategic merge patch:

```bash
kubectl patch deployment request-guard-mcp -n request-guard \
  --type strategic --patch-file deploy/k8s/geoip-patch.example.yaml
```

## Health Checks

```bash
# Liveness
curl http://localhost:8085/health

# Readiness
curl http://localhost:8085/ready

# Metrics (Prometheus)
curl http://localhost:8085/metrics
```

## WebSocket Testing

```bash
# Install wscat
npm install -g wscat

# Connect and classify
wscat -H "Authorization: $(echo -n 'Bearer ')$YOUR_TOKEN" -c ws://localhost:8085/mcp
> {"jsonrpc":"2.0","id":1,"method":"classify","params":{"user_agent":"GPTBot/1.0","path":"/"}}
```

## HTTP JSON-RPC Testing

```bash
curl -fsS http://localhost:8085/mcp \
  -H "Authorization: Bearer $YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"classify","params":{"user_agent":"GPTBot/1.0","path":"/"}}'
```

JSON-RPC notifications (requests without an `id`) return HTTP 204. JSON-RPC
tool errors use an HTTP 200 response with a JSON-RPC `error` object.

## Loading reputation and canary data

The default Redis prefix is `request_guard`. Threat records are JSON values in
the `request_guard:threats:<type>` hash, keyed by normalized indicators:

```bash
redis-cli -u "$MCP_REDIS_URL" HSET request_guard:threats:ip 198.51.100.9 \
  '{"threat_type":"scanner","severity":"high","source":"operator","last_seen":"2026-08-11T00:00:00Z"}'
```

For simple IP blocklists, add addresses to `request_guard:blocklist:ips`.
Canary tokens are never stored raw: SHA-256 the token and store a JSON record
in the `request_guard:canaries` hash. Successful evaluations append a bounded
event record to `request_guard:canary_events`.

## Common Operations

### View logs
```bash
# Docker
docker logs request-guard-mcp -f

# Kubernetes
kubectl logs -n request-guard -l app=request-guard-mcp -f
```

### Scale up
```bash
kubectl scale deployment request-guard-mcp -n request-guard --replicas=5
```

### Rolling restart
```bash
kubectl rollout restart deployment/request-guard-mcp -n request-guard
```

### Check HPA status
```bash
kubectl get hpa -n request-guard
```

## Troubleshooting

| Symptom | Likely Cause | Action |
|---------|-------------|--------|
| `UNAUTHENTICATED` errors | Missing/wrong token | Check `AUTH_TOKENS` env var |
| `RATE_LIMIT_EXCEEDED` | Too many concurrent requests | Increase `GLOBAL_CONCURRENCY` or add replicas |
| `INTEGRATION_UNAVAILABLE` | Required backend intentionally absent | Configure Redis, PostgreSQL, or MaxMind for that tool |
| `UPSTREAM_ERROR` | Configured backend failed during a tool call | Check Redis/PostgreSQL connectivity and MMDB readability |
| `TIMEOUT` errors | Slow backend or overloaded server | Check backend latency and concurrency limits |
| High memory usage | Cache too large | Reduce `moka` capacity or lower TTL |
| Pod OOM kill | Memory limit too low | Increase `limits.memory` in deployment.yaml |

## Upgrading

1. Update the image tag in `deployment.yaml`.
2. Apply: `kubectl apply -f deploy/k8s/deployment.yaml`.
3. Monitor: `kubectl rollout status deployment/request-guard-mcp -n request-guard`.
4. Rollback if needed: `kubectl rollout undo deployment/request-guard-mcp -n request-guard`.
