# Ingress fairness boundary

Request Guard v1.0.0 caps each non-upgraded HTTP/1 connection at
about 120 seconds after its first request and 128 requests. These are
per-connection limits. A client can reconnect and compete for the server's
global `max_connections` slots; they do not guarantee fair service between
clients. Published v0.1.5 does not include those HTTP/1 age and request caps.

For an externally reachable deployment, terminate TLS at a trusted reverse
proxy and apply client header/body deadlines, concurrent request and rate
limits **before** forwarding to Request Guard. Restrict the unauthenticated
`/health`, `/ready`, and `/metrics` paths to monitoring sources. Size limits
and values depend on your legitimate client concurrency; a single per-IP
quota can unfairly throttle clients sharing NAT. Also constrain requests
from distributed sources at the edge. Do not expose the plain HTTP/WebSocket
backend directly to untrusted networks.

`scripts/probe_nginx_ingress.py /path/to/request-guard-mcp` runs a disposable
loopback nginx proxy and packaged binary with two backend slots. It checks
three bursts of fresh client requests, a concurrent-request rejection, a
partial-header deadline, three further reconnect waves from separate loopback
source addresses, fresh-source recovery, authenticated MCP initialization,
and an authenticated WebSocket upgrade. The temporary config uses distinct
429 and test-only 430 responses to distinguish proxy rate and concurrency
rejections from backend responses. The probe's 2 requests/second, burst 2,
one-active-request/address,
and short timeouts are **test values**, not recommended production defaults.
It requires a locally installed `nginx`; it does not touch the host nginx
service, use Docker, or set up TLS. The temporary config is a test fixture,
not a hardened deployment template. It includes WebSocket
Upgrade forwarding and closes non-upgraded upstream HTTP connections.

The expanded probe passed against the checksum-verified public v1.0.0 Linux
x64 archive on 2026-10-28. The three multi-source waves used `127.0.0.2` to
`127.0.0.4`, with `127.0.0.10` as a fresh-source recovery check. These are
loopback aliases on one host, so this result does not model independent
networks, a real CDN/WAF, or production TLS ingress.

This bounded check does not prove fairness across distributed IPs, sustained
large-client workloads, NAT sharing, a full WebSocket tool exchange, production TLS policy,
or that your deployed ingress limits remain effective after changes. Qualify
your own proxy configuration and legitimate MCP clients before relying on it.
