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
  ghcr.io/rhamenator/ai-scraping-defense-mcp:latest
```

### Docker Compose (with Redis + PostgreSQL)
```bash
cd docker
AUTH_TOKENS=your_token docker compose up -d
```

### Kubernetes
```bash
# Create secrets
kubectl create secret generic mcp-secrets \
  --namespace ai-defense \
  --from-literal=auth_tokens=your_strong_token

# Apply manifests
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/hpa.yaml
kubectl apply -f deploy/k8s/networkpolicy.yaml
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

## Common Operations

### View logs
```bash
# Docker
docker logs ai-scraping-defense-mcp -f

# Kubernetes
kubectl logs -n ai-defense -l app=ai-scraping-defense-mcp -f
```

### Scale up
```bash
kubectl scale deployment ai-scraping-defense-mcp -n ai-defense --replicas=5
```

### Rolling restart
```bash
kubectl rollout restart deployment/ai-scraping-defense-mcp -n ai-defense
```

### Check HPA status
```bash
kubectl get hpa -n ai-defense
```

## Troubleshooting

| Symptom | Likely Cause | Action |
|---------|-------------|--------|
| `UNAUTHENTICATED` errors | Missing/wrong token | Check `AUTH_TOKENS` env var |
| `RATE_LIMIT_EXCEEDED` | Too many concurrent requests | Increase `GLOBAL_CONCURRENCY` or add replicas |
| `TIMEOUT` errors | Slow enrichment integrations | Check Redis/Postgres connectivity |
| High memory usage | Cache too large | Reduce `moka` capacity or lower TTL |
| Pod OOM kill | Memory limit too low | Increase `limits.memory` in deployment.yaml |

## Upgrading

1. Update the image tag in `deployment.yaml`.
2. Apply: `kubectl apply -f deploy/k8s/deployment.yaml`.
3. Monitor: `kubectl rollout status deployment/ai-scraping-defense-mcp -n ai-defense`.
4. Rollback if needed: `kubectl rollout undo deployment/ai-scraping-defense-mcp -n ai-defense`.
