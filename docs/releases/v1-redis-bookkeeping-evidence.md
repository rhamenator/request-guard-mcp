# Private v1 candidate Redis bookkeeping outage probe

The private `v1.0.0-rc.3` Linux x64 archive from GitHub run
`39715909418` contained binary SHA256
`bd7e7ec539873aa36c5d1fb378af0eec5c2341cb8c77d24f273b2e86ab9a7436`.
With a healthy Redis 7.2 container, a synthetic authenticated `classify` call
completed in 0.002 seconds. After pausing Redis, it still returned HTTP 200
with a normal tool result, but three calls took 2.506, 2.004 and 2.005 seconds
despite a configured two-second classify dispatch timeout. MCP `ping` remained
available.

The development build with the 500 ms best-effort Redis start/finish bounds,
SHA256 `689afe84182ff28ffcb5635983c1ba2bbf66ffa35f9ab9589f776f149776fd4a`,
returned the same normal classify result in 1.511, 1.509 and 1.509 seconds
with Redis paused;
healthy classify took 0.006 seconds. The test Redis image digest was
`redis@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0`.

Reproduce on an owned Linux lab host with Docker and an extracted binary:

```sh
python3 scripts/adversarial_redis_bookkeeping_probe.py /path/to/request-guard-mcp \
  --redis-image redis@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0
```

The script uses synthetic TEST-NET input and a synthetic bearer token, pauses
only its own Redis container, first verifies Redis health, runs from a clean
temporary directory with a restricted environment and random test ports,
checks classify and ping response shapes, and removes the container. Its
default gate requires the slowest of three paused classify calls to complete
in less than 2.25 seconds. The old private binary fails that gate; the changed
development binary passes. This is one bounded loopback comparison, not a
latency service-level objective or a complete Redis outage qualification.
Redis-dependent tools and cache operations have separate failure behavior;
the remaining ~1 second of outage latency is not attributed by this probe.
Both operation-record call sites use the same 500 ms deadline helper; a unit
test proves the helper cancels a pending record, but completion recording was
not independently paused at that exact phase. A timed-out Redis command may
still leave a stale active record until trim/expiry. The final v1 release must
replay this gate on exact packaged assets after all source fixes are merged.
