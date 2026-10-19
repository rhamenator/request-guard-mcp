# v0.1.1 experimental candidate evidence

This is evidence for a **local integration candidate**, not a claim that every
release platform or deployment mode has passed the full adversarial gate. The
official release assets must pass their own CI packaging and fresh-install
checks before publication.

On 2026-10-19 UTC, the integration worktree combined the PostgreSQL caller
isolation, HTTP slow-client limits, encoded-path detection, redacted config
snapshots, and v0.1.1 version branches at commit
`2972b36834eb822fcc68808666ee3898b67451ce`. The Linux x64 release binary
had SHA-256 `a7605bbbf3dd4734de85f32ed5219a866775d43612d22ad534170f3a4dda9789`;
its local archive had SHA-256
`2720dbff051208455b4037e938103944758efe16fb26818bc8b6f4f2c8449f3e`.
These hashes identify this local build, not reproducible bytes across builders.

The following checks passed against the combined source or packaged Linux
binary:

- `cargo test --locked --all-features -q`: all unit and integration suites
  passed. OpenSnitch initially denied loopback connections from the new test
  executable; exact-path allow rules were applied and the full suite rerun.
- `cargo fmt --check` and
  `cargo clippy --locked --all-targets --all-features -- -D warnings`: passed.
- `cargo build --locked --release -q`, `scripts/package_release.py`, and
  `sha256sum -c` from the artifact directory: passed.
- `python3 scripts/inspector_smoke.py` against the packaged binary: authentication,
  `initialize`, `tools/list` (23 tools), `classify`, and `explain` passed with
  official Inspector 2.5.0.
- `scripts/adversarial_probe.py`: 7/7 HTTP cases passed, including absent and
  wrong bearer tokens, malformed JSON, invalid parameter type, injected text
  treated as data, and oversized body rejection.
- `scripts/adversarial_ws_probe.py`: 6/6 WebSocket cases passed, including
  authentication, upgrade, initialization, malformed JSON, and tool listing.
- A bounded local socket probe with two-second read deadlines and a
  two-connection cap observed incomplete headers close, incomplete authorized
  bodies return HTTP 408, and a third connection shed: 3/3 passed.
- CI for the PostgreSQL isolation branch ran a real PostgreSQL service and
  passed the same-public-ID/different-caller integration case.

The independent Claude Code review identified slow HTTP clients, globally
addressable PostgreSQL request IDs, encoded-path evasion, and an unredacted
OTLP configuration URL. The four integration branches address those findings.
The review also noted incomplete JSON-RPC validation and limited signal inputs;
[issue #59](https://github.com/rhamenator/request-guard-mcp/issues/59) tracks
strict envelope conformance. The server's documented client and classifier limits still apply. This local
candidate did not exercise sustained exhaustion, backend failure/recovery,
other MCP clients, or Windows/macOS runtime outside release CI. Those gaps
remain open for the full production-readiness gate.
