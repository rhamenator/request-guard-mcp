# MCP Inspector interoperability evidence

The installed server must answer the standard MCP methods before its companion
skill can be offered to a buyer. The published v0.1.0 binary predates the
standard method dispatcher; use a candidate built from a newer commit, not the
existing v0.1.0 release. This document records a client check, not a stable
release approval.

## Reproduce

```bash
git clone https://github.com/rhamenator/request-guard-mcp.git
cd request-guard-mcp
cargo build --locked --release
python3 scripts/inspector_smoke.py target/release/request-guard-mcp
```

The smoke script starts the binary on a temporary loopback port with a random
bearer token, installs `@modelcontextprotocol/inspector@2.5.0` in a temporary
directory with npm, then invokes its CLI entrypoint with Node.js using
`--cli --transport http --method ... --format json`. It checks the 2025-06-18
initialize response, missing-token rejection, all advertised tool definitions, a `classify` structured
verdict, and an `explain` result with contributing factors. It exits nonzero
if any step fails. Node.js 22.19.0 or newer, npm, and package registry access (or a cached
Inspector package) are required. No Redis, PostgreSQL, MaxMind data, or
application credential is needed for these two core tools.

## Observed on 2026-10-18

- Source: `main` at `6bfe227` (the first commit with standard method dispatch).
- Local development build and official Inspector 2.5.0: all four checks passed.
- `tools/list`: 23 advertised contracts, including `classify` and `explain`.
- `classify`: returned `isError: false` and a structured `block` verdict for
  the synthetic GPTBot request.
- `explain`: returned `isError: false` with contributing factors for the same
  request metadata. Inspector requires `--tool-args-json` for its nested
  `classification` object; flat `--tool-arg` input yielded `INVALID_REQUEST`.
- An absent token was rejected at HTTP 401; a wrong token at 403. Inspector
  attempts interactive OAuth on a 401, so a noninteractive absent-token run
  reports `auth_required` rather than a server-side MCP result.
- Inspector `tools/list --strict` reported 0 errors and 6 portability warnings
  for unconstrained nested input schemas. Schema precision remains follow-up
  work; these warnings did not prevent the two core calls.

## Local candidate bundle

The same clean clone was advanced to documentation and smoke-script commit
`910047b81f5173bee65ccddea9335240dce3148b` and packaged using:

```bash
cargo build --locked --release
python3 scripts/package_release.py \
  --version 0.1.0-rc.2+910047b --target . --platform linux-x64
sha256sum artifacts/request-guard-mcp-0.1.0-rc.2+910047b-linux-x64.tar.gz
```

The local Linux x64 archive checksum was
`9c36a7d79cc9b36cde23bcceedfd5a0644abd6f5e03fd4b75b89b9d91eeebcfb`;
the contained binary checksum was
`eb738f3e0787b62ccd768d8326f213d0cb63b5f2311ae47468391356aeb5b6d9`.
Archive contents were inspected: binary, `.env.example`, `Cargo.lock`,
`LICENSE`, and `README.md`. After extraction, the same four Inspector smoke
checks passed against the bundled binary. The binary still reports Cargo
version `0.1.0`; the suffix labels this local candidate and is not a published
release. The archive format currently embeds file timestamps, so this checksum
identifies this build rather than promising bit-for-bit identical archives on
another host.

The broader adversarial gate remains open. This candidate has not been
uploaded as a release or marketplace package.

## Current client limits

The server offers HTTP POST JSON-RPC and a custom WebSocket JSON-RPC endpoint.
It does not provide stdio, SSE GET streaming, OAuth discovery, resources,
prompts, or the 2026-07-28 `server/discover` lifecycle. Tool availability may
depend on optional backends; `classify` and `explain` do not. The skill does
not make unrelated agent HTTP traffic pass through this server.
