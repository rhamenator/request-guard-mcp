# Adversarial release gate

Stable releases require a repeatable adversarial run against the packaged server's actual HTTP and WebSocket interfaces in an authorized lab. Record the tested commit and binary digest, configuration with secrets redacted, exact commands, tool versions, expected and observed outcomes, resource measurements, fixes, and residual limits. A passing unit suite or vulnerability scan alone does not satisfy this gate.

The [v1.0 evidence map](releases/v1-gate-evidence-map.md) distinguishes existing experimental-release results from checks that must be repeated on the exact stable candidate.

Stable tag jobs use the GitHub `stable-release` environment, configured with
`rhamenator` as its required reviewer. The native Release workflow validates
the tag version and main ancestry, then waits for approval before building
archives. The Container workflow validates the same tag before requesting
approval and pushing either platform digest. The owner should approve those
jobs only after issue #125 has the exact-candidate evidence and independent
review. This is a deliberate owner pause, not an independent approval:
repository administrators can bypass the environment protection. A passing
PR or private `workflow_dispatch` candidate does not authorize a stable tag.
Before a stable release, verify the environment still has the required-reviewer
protection rule; an unprotected or missing environment does not satisfy this
gate. Experimental and private-candidate paths remain automatic.

At minimum, exercise authentication boundaries, malformed JSON-RPC and MCP frames, invalid and oversized inputs, prompt-injection text treated as request data, bot-evasion variations, concurrency and slow clients, backend failure and recovery, and logging of sensitive fields. Use Kali and Ubuntu lab VMs when available; scope scanners to the owned test endpoint, record their request counts, and bound runtime and rate to preserve shared host responsiveness. Confirm each exploit or anomaly with a regression test, rerun the affected probe, then rerun the full gate. Reconcile independent Claude Code and Codex reviews with the observed runtime results and document remaining limits before a release.

The HTTP transport regression suite checks that valid JSON with an invalid JSON-RPC
version, ID type, or envelope receives `-32600` with a null ID; malformed JSON
receives `-32700`. CI also runs `scripts/ci_adversarial_smoke.py` against its
freshly built server on loopback. It records the binary SHA-256 and runs bounded
HTTP and WebSocket probes with a temporary synthetic token. The probes cover
authentication boundaries, malformed JSON, invalid envelopes, invalid tool
parameters, prompt-injection text as request data, and declared oversized
HTTP bodies. The same CI job calls `tools/call` over HTTP for 19 bounded
classifier cases: a benign control, two named-bot user-agent variants, raw
through four-times percent-encoded `.env` paths, two encoded separator
variants, four scanner user agents, three sensitive-path variants, and two
near-match path controls. It checks expected
signal names without treating a score as a visitor-block decision. These
checks do not complete this gate. CI uses a 4096-byte request limit and
one-second header/body timeouts to test incomplete headers, a stalled
authenticated body, a chunked body over the limit, and a healthy request
afterward. The slow-client probe is bounded to four connections and a
30-second subprocess cap; it does not simulate sustained exhaustion.
With that same 4096-byte cap, the WebSocket probe checks one oversized frame,
a fragmented message whose combined size exceeds the cap, and a fresh
connection afterward. The server must send WebSocket close code 1009 for
oversized frames and completed fragmented messages; a hard TCP close fails
the probe. See `adversarial-evidence-ws-close-2026-10-19.md` for the fix.
CI also starts a second loopback server with `MAX_CONNECTIONS=2` and a
ten-second header deadline. It verifies two incomplete-header connections
remain pending, checks that a third connection is shed, releases the held connections, and
checks that an authenticated `ping` succeeds. This bounded probe does not
establish sustained exhaustion resistance; see
`adversarial-evidence-connection-cap-2026-10-19.md`.
The CI fixture also leaves Redis unconfigured, calls `threat_lookup` through
standard MCP `tools/call`, checks its deterministic `INTEGRATION_UNAVAILABLE`
error, then verifies `classify` still succeeds on the same server. This proves
one optional-backend failure path and core-tool recovery; it does not prove
recovery from a live Redis or PostgreSQL outage. See
`adversarial-evidence-backend-2026-10-19.md`.
The CI wrapper also starts an isolated debug-log server, sends a rejected
synthetic bearer token and an authenticated `classify` call containing a
synthetic request marker, then confirms expected log events occurred without
either value appearing in a bounded capture. This checks direct log leakage
for those calls, not every tool, proxy, collector, or encoding. See
`adversarial-evidence-logs-2026-10-19.md`.
CI also sends 128 deterministic malformed JSON-RPC envelopes, verifies each
gets a structured error, and confirms a healthy authenticated ping afterward.
On a two-slot listener it sheds 128 bounded excess TCP connections and then
checks recovery. These probes cap their counts at 256, avoid sustained load,
and run without additional Python dependencies. The expanded Kali-to-Ubuntu
evidence, including a live Redis outage and cache-scope observation, is in
`adversarial-evidence-expanded-2026-10-19.md`.
The live PostgreSQL outage/recovery procedure and 9/9 Kali-to-Ubuntu result
are in `adversarial-postgres-kali-ubuntu-2026-10-19.md`; its reusable probe is
`scripts/adversarial_postgres_probe.py`.
The bounded Nmap and Nikto on-wire request counts and capture method are in
`adversarial-scanner-counts-kali-ubuntu-2026-10-19.md`.
The independent cross-project scanner/path evasion corpus, black-box misses,
and HTTP regression results are in `adversarial-classifier-parity-2026-10-19.md`.
The initial bounded 63-second slow-header saturation run, including per-cycle
recovery, server RSS, and sampled host load/I/O pressure, is in
`adversarial-sustained-exhaustion-2026-10-19.md`. The public v0.1.4 archive
was later tested from Kali against Ubuntu, with packaged-binary saturation,
scanner counts, transport probes, and residual limits recorded in
`releases/v0.1.4-kali-ubuntu-adversarial.md`. Its independent reviews were
reconciled in PR #119, and release issue #118 was completed before v0.1.4
became GitHub Latest.
The public v0.1.4 executable also passed the 13-case deterministic HTTP
envelope matrix in `releases/v0.1.4-envelope-matrix.md`, including malformed
JSON, array input, ID types, notifications, client responses, and recovery.
This does not cover the custom WebSocket transport or optional SSE behavior.
The exact same public executable passed the 22-case custom WebSocket envelope
and lifecycle probe and a fresh official Inspector 2.5.0 client run; see
`releases/v0.1.4-ws-envelope-matrix.md`. Optional SSE and a broader client
matrix remain outside the implemented v0.1.4 transport scope.

The published v0.1.5 Linux amd64 GHCR image passed authenticated MCP,
malformed-envelope, classifier, connection-cap, and 63-second bounded
slow-header saturation probes. Its bounded container logs were checked for
absence of the synthetic bearer. The index also contains an arm64
manifest and linked attestations; runtime execution in this run was amd64.
See `releases/v0.1.5-public-ghcr-adversarial.md`. This adds to the v0.1.5
public native, Kali-to-Ubuntu, backend, and TLS evidence, but does not close
the stable v1.0 gate in issue #125.

For future main and tag container builds, native amd64 and arm64 GitHub runners
now pull each just-pushed immutable platform digest and run bounded authenticated
HTTP, WebSocket, and classifier probes before their digests can be assembled into
the multiarch tag. `scripts/smoke_native_container.py` verifies that Docker
loaded the expected architecture and reaches the container over its runner's
bridge network. This checks native arm64 execution in CI, but it does not
retroactively qualify the published v0.1.5 arm64 image or replace the full
candidate adversarial gate.

For an already published index, run the manual **Qualify Published Container**
workflow with its exact `sha256:` index digest. It pulls the same immutable
index on native amd64 and arm64 runners, verifies the selected image
architecture, and runs the same 51 bounded HTTP/WebSocket/classifier cases.
For example, `gh workflow run qualify-published-container.yml -f
digest=sha256:...` uses the workflow on the default branch; record the run URL,
workflow commit, digest, and both job results with the release evidence. This
is a client and classifier smoke, not a substitute for backend outages, TLS,
resource exhaustion, or independent stable-release review.

The stdlib-only `scripts/adversarial_probe.py` is a first HTTP smoke subset. Start a lab server with a temporary token of at least 32 characters, then run:

```bash
printf '%s\n' "$LAB_TOKEN" | python3 scripts/adversarial_probe.py --url http://LAB_HOST:8085 \
  --max-request-bytes 1048576
printf '%s\n' "$LAB_TOKEN" | python3 scripts/adversarial_ws_probe.py \
  --host LAB_HOST --port 8085
printf '%s\n' "$LAB_TOKEN" | python3 scripts/adversarial_classifier_probe.py \
  --url http://LAB_HOST:8085
```

Set `--max-request-bytes` to the server's configured `MCP__LIMITS__MAX_REQUEST_BYTES`. The HTTP probes refuse to follow redirects, so the bearer token stays scoped to the explicitly named lab endpoint. All probes can read a token from stdin; omit the first HTTP probe's `--token` argument to do so. The WebSocket probe tests bounded handshake and frame cases. Do not put the token in committed files or published logs. None of the probes prints the token. This subset does not validate sustained exhaustion, backend failures, unknown user-agent evasions, or complete MCP interoperability; those cases need separate evidence before release.

To test WebSocket size limits manually, use a lab server configured with
`MCP__LIMITS__MAX_REQUEST_BYTES=4096` and add
`--max-request-bytes 4096` to the WebSocket probe command. The probe caps
its test size at 65536 bytes; omitting the option keeps the original
handshake/protocol subset.

For the slow-client subset, start a separate lab server with
`MCP__LIMITS__MAX_REQUEST_BYTES=4096`,
`MCP__LIMITS__HTTP_HEADER_TIMEOUT_SECS=1`, and
`MCP__LIMITS__HTTP_BODY_TIMEOUT_SECS=1`, then run:

```bash
printf '%s\n' "$LAB_TOKEN" | python3 scripts/adversarial_slow_client_probe.py \
  --host LAB_HOST --port 8085 --max-request-bytes 4096
```
