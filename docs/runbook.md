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

### Docker Compose (local demo with Redis, PostgreSQL, Prometheus and Grafana)
```bash
# From the repository root; this writes a private .env with all six required
# application and backing-service values.
python scripts/configure_credentials.py
make docker-compose-up
curl -fsS http://127.0.0.1:8085/health
curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22request-guard-mcp%22%7D'
```

Open `http://127.0.0.1:3000` for Grafana. Log in as `admin` with
`GRAFANA_ADMIN_PASSWORD` from your private `.env`; the default Prometheus
datasource points to the local MCP scrape. The three published host ports bind
to loopback only. Redis and PostgreSQL data are stored in named volumes. The
MCP server creates its PostgreSQL tables and indexes idempotently at startup.
If a local port is occupied, set `MCP_HOST_PORT`, `PROMETHEUS_HOST_PORT`, or
`GRAFANA_HOST_PORT` in `.env` and use those ports for the local checks.
Use `make docker-compose-down` to stop the stack; `down --volumes` also deletes
the demo data.

This is a local demo: the Redis connection uses plaintext `redis://` even
when it has a password. Keep it on a trusted isolated network; do not expose
it across an untrusted link or publish the demo Redis service externally.
The MCP `/metrics` endpoint is unauthenticated within the Compose network.
The pinned Prometheus and Grafana image digests are reviewed inputs for this
example; update them when applying security patches.
For a production PostgreSQL server across a
network, use `sslmode=verify-full` and a trusted CA rather than the demo URL.

### Kubernetes
```bash
# Create the namespace first
kubectl apply -f deploy/k8s/namespace.yaml

# Create consistent backend/application secrets. This local demo uses URL-safe
# passwords and plaintext in-cluster Redis/PostgreSQL links. Isolate the Redis
# link; for production PostgreSQL across a network use sslmode=verify-full
# with a trusted CA. This server build does not support rediss://.
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

In published v0.1.4, accepted JSON-RPC notifications and client responses
return HTTP 202 with no body, as required by MCP 2025-06-18. The earlier
v0.1.3 release returns HTTP 204 with no body. JSON-RPC tool errors use an
HTTP 200 response with a JSON-RPC `error` object.

## Loading reputation and canary data

The default Redis prefix is `request_guard`; substitute your configured prefix
in every command below. Open an authenticated Redis CLI session against the
intended database using a credential method that does not place passwords in
process arguments. Threat records are JSON values in the
`request_guard:threats:<type>` hash, keyed by normalized indicators:

For domain records, seed lowercase ASCII keys without a trailing DNS dot; use
punycode for internationalized domains. Existing noncanonical keys need
operator migration because the lookup uses the normalized spelling. For URL
records, use the exact lookup string with a lowercase `http://` or `https://`
scheme; URL path and host spelling are not otherwise canonicalized. A lookup
miss is not a general safety verdict.

```text
HSET request_guard:threats:ip 198.51.100.9 '{"threat_type":"scanner","severity":"high","source":"operator","last_seen":"2026-08-11T00:00:00Z"}'
```

For simple IP blocklists, add addresses to `request_guard:blocklist:ips`.
For ASN reputation, seed `request_guard:threats:asn` with a bare decimal ASN
field such as `15169`, not `AS15169`. On development main, `enrich_asn`
separately reports whether that Redis record or an ASN MMDB record was found;
an absent record yields an unverified 0.1 baseline, not a safe verdict.
On development main, `enrich_ip` and `threat_lookup` check the canonical IPv4
key (`198.51.100.9`) first for IPv4-mapped IPv6 input
(`::ffff:198.51.100.9`), then the literal mapped key if the canonical key is
absent. Store new IPv4 threat and blocklist entries under the IPv4 spelling;
existing mapped keys remain readable. Published v0.1.5 does not perform this
alias lookup.
On development main, seed new IPv6 threat and blocklist keys in canonical
compressed spelling (for example, `2001:db8::1`). If an older record uses a
valid noncanonical spelling such as `2001:0db8::1`, `threat_lookup` and
`enrich_ip` try the canonical key first and then that exact supplied spelling.
This fallback does not enumerate other IPv6 aliases: migrate legacy keys to
canonical spelling so callers need not know how each record was seeded.
Canary tokens are never stored raw: SHA-256 the token and store a JSON record
in the `request_guard:canaries` hash. Successful evaluations append a bounded
event record to `request_guard:canary_events`. The event list keeps at most
10,000 records but has no time-based TTL; the canary registry hash also has no
TTL. Each event contains `canary_id`, the SHA-256 `token_hash`, `triggered_at`,
and optional `context` (stored as an unredacted JSON value when its encoded
size is at most 4096 bytes; larger values become a SHA-256 digest, byte count,
and truncation marker). Events use
one Redis prefix across callers, without PostgreSQL's per-caller scope. Avoid
secrets and unnecessary personal data in context. Set an operator-managed
retention schedule. In an authenticated Redis CLI session against the intended
database, inspect the count before removing all current event records:

```text
LLEN request_guard:canary_events
UNLINK request_guard:canary_events
```

`UNLINK` discards the event history and frees the key asynchronously; export only what
your policy permits first. To retain fewer recent events instead, use
`LTRIM request_guard:canary_events 0 999` for the most recent 1000 entries;
it still provides no age-based expiry. These commands do not remove registered
canaries, Redis persistence/replica copies, or backups, and do not establish
physical erasure.

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

1. Verify the new release's published multiarch image digest and platform
   manifests, then replace the `@sha256:...` image reference in
   `deploy/k8s/deployment.yaml`. Update both `version` labels to the same
   release version; do not substitute a mutable tag for the digest.
2. Apply: `kubectl apply -f deploy/k8s/deployment.yaml`.
3. Monitor: `kubectl rollout status deployment/request-guard-mcp -n request-guard`.
4. To roll back, reapply the previous verified deployment manifest, including
   its image digest and both `version` labels, then monitor the rollout again.
   `kubectl rollout undo` alone does not restore the Deployment's metadata label.
