# Request Guard adversarial baseline — 2026-10-18

This is an initial lab baseline, not a completed stable-release gate. Source baseline: `0e278b7` on `main`; the HTTP probe used the existing local debug binary. A packaged release artifact was not tested.

## Scope and setup

- Server: Request Guard on the host's libvirt NAT interface, `192.168.122.1:18085`, with a temporary synthetic bearer token. No Redis or PostgreSQL backend was configured.
- Scanner: owned `copperfin-kali-full` VM on `192.168.122.74`; Nmap 7.99 and Nikto 2.6.1.
- Only the Kali VM IP was temporarily allowed through UFW to this port. The rule was deleted, the test server stopped, and Kali confirmed `shut off` afterward.
- Host load before testing was about 1.1, with no running VMs. The other MCP chats were notified before and after the lab window.

## Commands and observations

| Command or case | Observation |
| --- | --- |
| `python3 scripts/adversarial_probe.py --url http://127.0.0.1:18085 --token "$LAB_TOKEN"` | 7/7 passed: missing auth 401, wrong auth 403, authorized health 200, malformed JSON-RPC `-32700`, invalid parameter type rejected, injection text handled as classification data without token reflection, oversized body 413. |
| `nmap -Pn -sT -sV -p 18085 --script http-methods,http-headers 192.168.122.1` | Port open; malformed service probes received HTTP 400, unknown paths 404; no service version identified. |
| `nikto -host http://192.168.122.1:18085 -maxtime 30s -timeout 2 -nointeractive -Tuning 1234a` | 4,409 requests, zero transport errors, seven header-related reports. The actionable API response finding was absent `X-Content-Type-Options`. |
| `cargo test --test http_transport` after fix | 3/3 passed, including regression assertion for `X-Content-Type-Options: nosniff` on an unauthenticated response. |
| `cargo test --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo fmt --check`, `cargo build --locked` | Passed after the fix. |
| Rebuilt local server: `curl -sSI http://127.0.0.1:18085/health` and the seven-case probe | `x-content-type-options: nosniff` observed; probe remained 7/7. |

Nikto also suggested HSTS, CSP, Permissions-Policy, and Referrer-Policy. The server is plain HTTP behind an intended TLS-terminating proxy, so HSTS belongs at that proxy. Browser document policies have limited meaning for a JSON-RPC API and require deployment-specific review. The `nosniff` finding was fixed in the server.

## Probe review follow-up

Review found that the first probe could follow a redirect with its bearer token and assumed a 1 MiB body limit. The probe now refuses redirects and accepts `--max-request-bytes` to match the tested server configuration. Stdlib regression tests confirmed that a redirect target received no request and that the oversized declaration is exactly one byte above a configured 2 MiB limit. Both tests passed with Python warnings treated as errors; the seven live HTTP cases still passed.

## Gaps before stable release

Repeat against the actual packaged artifact. Test authenticated and unauthenticated WebSocket frames, slow clients and bounded concurrency, Redis/PostgreSQL failures and recovery, bot-evasion corpus, log redaction, and MCP client interoperability. Record timings, memory, logs, and artifact digest. Independent review must assess any remaining findings.
