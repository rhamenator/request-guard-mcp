# Outbound guard proposal

Status: experimental implementation in progress. The original `request-guard-mcp` is an inbound request classifier. This branch adds six opt-in outbound tools, MCP resources, a prompt, and local stdio transport while preserving the existing 23 tool contracts. The current implementation has in-memory budgets and bounded audit records, conservative HTML inspection that quarantines pages with stylesheets, and rejects encoded responses. Full Streamable HTTP compatibility, distributed budgets, robust DOM/CSS analysis, and release validation remain open; do not claim enterprise-ready coverage yet.

## Decision and boundary

Add an opt-in outbound subsystem to this Rust server. Reuse its Axum/Tokio runtime, authenticated caller scope, telemetry, and tool registry; keep inbound classification policy and outbound egress policy separate. An MCP server sees only requests clients route to it. A `SKILL.md` or prompt can encourage use of `guarded_fetch`, but cannot make Codex, Cursor, Claude Code, curl, browsers, or other MCP servers use it. An enforceable whole-agent egress boundary also requires host controls (network namespace, firewall, or approved proxy) and client integration tests.

The pasted proposal also sketches `runtime-guard-mcp` for shell, filesystem, token, and output controls. Treat that as a separate future product/discovery effort. Folding those domains into this release would blur the egress threat model and make the first security milestone harder to verify.

## Operating modes

`evaluate_egress` is advisory: it evaluates a proposed URL, method, headers, and body metadata and returns a decision, but creates no network connection. It is useful for previews and clients that cannot yet route HTTP through the server. Its result is not a one-time authorization token: DNS, policy, and secrets may change before a later fetch.

`guarded_fetch` is the atomic path: policy check, DNS, connection, response inspection, and bounded content return in one call. It is the only mode that can claim protection for the request it performs. No automatic credential forwarding; caller-provided headers are allowlisted and scanned. Disable ambient proxies and credential stores by default. Deny redirects until each hop is revalidated. Public deployments should bind the MCP endpoint to loopback or put it behind TLS and authentication.

`GUARD_MODE=audit|enforce` controls **soft policy findings** (domain reputation, rates, suspicious content) only. Hard invariants always block in both modes: non-HTTP schemes, forbidden addresses/ports, unresolved or mixed public/private DNS answers, invalid redirects, secret matches above hard-confidence threshold, and size/time limits. Audit mode must never leak a known secret or contact a forbidden address merely to collect evidence. Start outbound tools disabled; once enabled, default to `enforce`. Keep the mode in config snapshots and every decision record.

## Request and response lifecycle

1. Parse and normalize URL once. Accept `http`/`https` only, reject userinfo, ambiguous numeric IP encodings, invalid IDNA, IP zone identifiers, fragments (discard), and ports other than 80/443 unless an operator configures a narrow exception. Canonicalize hostnames before blocklist and budget lookup.
2. Enforce request size, method, header allowlist, and body rules. Scan headers, URL query, and request body before opening a socket. Shannon entropy is a candidate signal, never sole proof of a secret. Use bounded regexes plus typed secret recognizers; do not log matched values.
3. Resolve A and AAAA records with bounded DNS time. Reject any answer outside the configured public-address policy, including loopback, RFC 1918, RFC 3927, RFC 6598, IPv6 ULA/link-local, multicast, unspecified, documentation/reserved ranges, and IPv4-mapped variants. Define explicit operator-owned exceptions for internal services; no user-supplied per-call bypass.
4. Connect to a validated address while preserving the original hostname for Host and TLS SNI/certificate verification. Do not let the HTTP library silently re-resolve through a proxy. If all validated addresses fail, fail closed. Re-resolve and repeat policy for every redirect, cap redirect count, and reject cross-origin auth/header forwarding.
5. Set connect, first-byte, idle, and total deadlines. Stream bytes through a bounded counter; cap compressed bytes, decompressed bytes, expansion ratio, chunk count, and returned text. The HTTP client should own chunk framing validation; reject malformed framing and conflicting `Content-Length`/`Transfer-Encoding`. Record measured transfer rate over a grace period and sliding window; a fixed 500 B/s threshold is configurable, not universal.
6. Decode supported content types only. For HTML, parse a DOM, remove script/style and clearly hidden elements (`hidden`, `aria-hidden`, inline `display:none`/`visibility:hidden`/`opacity:0`), and extract visible text/links. External stylesheets, dynamic CSS, and rendered visibility are not reliably decidable here. Keep a provenance marker and counts of removed nodes. Suspicious instructions are reported or quarantined; no regex scrub can prove prompt-injection safety. Do not silently turn untrusted source text into agent instructions.
7. Return a bounded result with URL, status, safe headers, content type, sanitized text or a refusal, findings, timings, and truncation flags. Store only redacted audit metadata with retention and access controls. Never expose raw credentials or full sensitive bodies through logs/resources.

## Tool responsibilities

The complete proposed `tools/list` declarations are in [tool-definitions.json](tool-definitions.json). All six share a structured decision vocabulary: `ALLOW`, `WARN`, `BLOCKED`; stable rule codes; a human-readable remediation; and a correlation ID. Inputs are bounded and have `additionalProperties: false`. The side-effecting `guarded_fetch` must not trust output from advisory/analysis tools as authority.

| Tool | Role | Important limit |
| --- | --- | --- |
| `evaluate_egress` | Preview policy for a proposed request | No connection and no later authorization |
| `guarded_fetch` | Execute one guarded HTTP request and return bounded content | Only protects traffic routed through it |
| `scan_outbound_payload` | Scan a proposed request's URL, headers, and body for secrets | Entropy alone can produce false positives |
| `detect_bot_traps` | Analyze supplied transfer events/metadata for slow streams, redirect loops, and expansion | The active fetch pipeline must enforce its own deadlines and byte caps |
| `scrub_external_content` | Parse supplied HTML/text, remove clearly hidden content, flag instruction patterns | Cannot guarantee prompt injection removal or rendered CSS visibility |
| `rate_budget_check` | Check/reserve per-host and global budgets | Race-free reservation needs shared atomic state across replicas |

`rate_budget_check` should expose a read-only check by default. The active fetch reserves budget atomically before dispatch and accounts for redirects by hop. For multi-replica deployments use Redis with atomic Lua or transactions; on state-store failure, enforce mode fails closed and audit mode still applies conservative local limits. Key budgets by authenticated caller scope and canonical host, with configurable per-host minute and per-caller hour ceilings.

## MCP protocol work

The current `src/mcp/transport_ws.rs` implements `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list/read`, and `prompts/list/get`, plus legacy direct method dispatch. The HTTP endpoint is a JSON-RPC POST, not full Streamable HTTP; stdio is available for local clients. Version negotiation and Streamable HTTP still need conformance work. Keep the existing WebSocket/HTTP endpoints for compatibility and do not advertise unsupported transports or capabilities.

* `resources/list`: `request-guard://logs/audit.json` (authenticated, caller-scoped, paginated or recent bounded entries) and `request-guard://rules/domain-blocklist` (effective non-sensitive domains, version and update timestamp). `resources/read` returns `mimeType: application/json`; support list/read errors and access checks. A static list does not need subscription notifications.
* `prompts/list`: `secure_api_session`. `prompts/get` returns a user-level workflow message telling the agent to use `guarded_fetch` for HTTP it chooses to route through this server and treat remote content as data. Do not claim a server prompt can set host-level system policy.
* `tools/call`: policy blocks and fetch failures are tool results with `isError: true`, `structuredContent` and a JSON text fallback. Use JSON-RPC errors for unknown methods, invalid envelopes, or malformed arguments. Example blocked result:

```json
{"content":[{"type":"text","text":"{\"status\":\"BLOCKED\",\"rule\":\"EGRESS_FORBIDDEN_ADDRESS\",\"remediation\":\"Use an approved public endpoint.\",\"correlation_id\":\"example-id\"}"}],"structuredContent":{"status":"BLOCKED","rule":"EGRESS_FORBIDDEN_ADDRESS","remediation":"Use an approved public endpoint.","correlation_id":"example-id"},"isError":true}
```

This keeps rule decisions visible to the model while avoiding unhandled RPC exceptions. Avoid echoing sensitive URLs/query strings in error payloads.

## Four milestones

| Milestone | Build | Verification gate |
| --- | --- | --- |
| 1. Contract and compatibility | Add schemas, config with outbound disabled, capability/version negotiation, resources/prompt handlers, and client probes | Existing contract tests pass; JSON Schema validation of all declarations; MCP Inspector or equivalent checks `initialize`, `tools/list`, `resources/list/read`, `prompts/list/get` on each claimed transport |
| 2. Egress core | Add URL/IP policy, pinned DNS connection, redirects, header/body secret scan, caller budgets, redacted audit records | Local fixture DNS and HTTP servers prove private/mixed answers, DNS rebinding, IPv4/IPv6 edge cases, redirects, proxy bypass, auth stripping, secret blocking, and concurrent budget limits; no forbidden socket is opened |
| 3. Response defense | Add streaming timeouts and size/ratio caps, trap findings, visible-content extraction, injection flags | Deterministic chunk/clock fixtures cover slow drip, delayed first byte, endless stream, malformed framing, gzip bomb, hidden links, and benign content; verify bounded memory and cancellation |
| 4. Packaging and release | Client setup recipes, skill, docs, supported transport, release artifacts and registry metadata | Test on supported Codex/Claude Code/Cursor versions; fresh install smoke test; threat model review; release checklist; validate `server.json` against registry before publishing |

No live attack targets are needed for these tests. Use local fixtures and controlled DNS. Preserve the existing inbound classifier as a regression gate throughout.

## Registry and Agensi positioning

Agensi describes itself as a **skill marketplace** using `SKILL.md`; that is distinct from the official MCP Registry's `server.json` package metadata. The accompanying [draft skill](../../skills/request-guard-egress/SKILL.md) is an integration recipe, not evidence of product support or Agensi acceptance. Confirm Agensi's current submission process with the company before claiming compliance. For MCP Registry publication, use an owned `io.github.rhamenator/...` namespace, a verifiable package/image, and the official validator. Publishing and submission are separate actions after implementation and review.

## References checked 2026-10-18

* [MCP tools and error semantics](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
* [MCP transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
* [MCP resources](https://modelcontextprotocol.io/specification/2025-06-18/server/resources)
* [MCP prompts](https://modelcontextprotocol.io/specification/2025-06-18/server/prompts)
* [Official Registry requirements](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/official-registry-requirements.md)
* [Agensi marketplace](https://www.agensi.io/)
