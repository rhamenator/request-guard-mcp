# v0.1.1-rc.1 packaged-server Kali evidence — 2026-10-18

This bounded, authorized run tested the published Linux x64 release archive against the owned `copperfin-kali-full` VM. It does **not** clear the v0.1.1 release gate: two denial-of-service concerns were reproduced, and the final candidate must be retested after fixes.

## Scope and artifact

- Release tag: `v0.1.1-rc.1`, commit `61a6ce30413bae5849f6735a2378b39228a4f99b`.
- Extracted server binary SHA-256: `324c83b484ecb6557571ad88f3baabf0a9296eb8c1671b3e048355e1b1e2c503`.
- Temporary host listener: `192.168.122.1:18086`, bearer authentication enabled with a freshly generated 32-byte-plus synthetic token; no Redis, PostgreSQL, or MaxMind service configured.
- Kali client: `192.168.122.74`, Nmap 7.99, Nikto 2.6.1, Python 3 standard library. The temporary UFW rule allowed only that IP to TCP 18086.
- Host before boot: load 1.34, I/O PSI full avg10/avg60 0.00/0.09%, 31 GiB available. After tests and shutdown: load 1.60, I/O PSI full avg10/avg60 0.00/0.00%. No other VMs were running. The Veeam local backup had finished; remote rclone sync continued. The owner temporarily overrode the Copperfin handoff's VM hold for this bounded run.

## Results

| Probe | Observation |
| --- | --- |
| `nmap -Pn -sT -sV -p 18086 --script http-methods,http-headers --max-retries 1 --host-timeout 60s 192.168.122.1` | Port reachable; malformed service probes received HTTP 400; unknown paths returned 404 with `X-Content-Type-Options: nosniff`. No service version identified. |
| `nikto -host http://192.168.122.1:18086 -maxtime 15s -timeout 2 -nointeractive -Tuning 1234a` | 4,409 requests in about 3 seconds, zero transport errors, five browser/TLS header suggestions. No new actionable server finding; HSTS belongs at the TLS proxy. |
| `scripts/adversarial_probe.py --url http://192.168.122.1:18086 --token <synthetic-token>` | 7/7 passed: missing/wrong auth, authorized RPC, malformed JSON, invalid parameter, instruction text treated as data, declared oversized body rejected. This probe does not stream a large body. |
| `scripts/adversarial_ws_probe.py --host 192.168.122.1 --port 18086` with token on stdin | 6/6 passed: missing/wrong auth, upgrade 101, initialize, malformed JSON `-32700`, `tools/list` returning 23 contracts. The committed version of this probe was rerun against the same packaged binary on loopback: 6/6. |
| One unauthenticated HTTP POST declared `Content-Length: 1000000`, sent one body byte, and waited two seconds | No authentication response during the two-second window. This reproduces body receipt before authorization; it does not by itself quantify maximum concurrent memory use. |
| 20 authenticated `tools/call` requests with distinct nonexistent tool names | `/metrics` distinct `mcp_request_duration_seconds_count{tool=...}` labels increased from 2 to 22, one per invented name. This confirms attacker-controlled metrics cardinality when a token holder can call the endpoint. |

## Cleanup and limits

The temporary server stopped, its token file was deleted, the exact UFW rule was removed, and libvirt confirmed Kali `shut off`. The source-side and Redis/PostgreSQL failure paths, slow headers, chunked-body limits, WebSocket oversized frames, sustained load, log redaction, and multi-token persistence isolation remain untested. Nmap/Nikto header suggestions require proxy/deployment context. The classifier regex fix from PR #44 was merged after this rc.1 artifact was built and is **not** covered by these artifact results.
