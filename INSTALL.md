# Install Request Guard MCP from a release bundle

For Linux x64, use the `linux-x64` archive on glibc systems and a separately
labeled `linux-x64-musl` archive on Alpine/musl. Releases v0.1.3 and newer include
both archives; v0.1.2 has only the glibc archive. If the selected release has no
musl archive, that release does not support Alpine.

Download the archive for your operating system and CPU from the GitHub release,
along with its matching `.sha256` file. Verify the archive before extracting it:

- Linux: `sha256sum -c request-guard-mcp-*.tar.gz.sha256`
- macOS: `shasum -a 256 -c request-guard-mcp-*.tar.gz.sha256`
- Windows PowerShell: compare `(Get-FileHash .\request-guard-mcp-*.zip -Algorithm SHA256).Hash`
  with the hash in the matching `.zip.sha256` file.

For future tagged releases built after the native provenance change, verify the
signed GitHub release-workflow attestation with a recent GitHub CLI and network
access:

```sh
gh attestation verify <archive> --repo rhamenator/request-guard-mcp \
  --signer-workflow rhamenator/request-guard-mcp/.github/workflows/release.yml \
  --source-ref refs/tags/<release-tag> --source-digest <reviewed-commit-sha>
```

Replace all placeholders with the exact downloaded archive, tag, and reviewed
commit. Private workflow-dispatch candidates intentionally have no public
attestation. The five native tagged-release lanes use Rust 1.99.1. After
starting the server, an authenticated MCP client can call `model_info` through
`tools/call` with empty arguments; its `build_info` reports the embedded source
commit, Rust version, and UTC build date. Compare the source commit to the
reviewed tag and attestation. The build date describes runner time; it does not
make archives bit-for-bit reproducible. A matching `.sha256` sidecar from the
same release detects corruption but is not independent provenance. Published
v0.1.5 predates this change and has no such native attestation.

Extract the archive, then work inside its `request-guard-mcp-<version>-<platform>`
folder. The server binary is already built; Rust, Cargo, Redis, PostgreSQL, and
MaxMind data are not needed for the core `classify` and `explain` tools.

1. Copy `.env.example` to `.env` (`cp .env.example .env` on Linux/macOS, or
   `Copy-Item .env.example .env` in PowerShell).
2. Replace `AUTH_TOKENS=replace_me_with_a_strong_token` in `.env` with a unique,
   randomly generated token of at least 32 characters. Keep `.env` private. For
   local-only use, change `MCP__HOST=0.0.0.0` to `MCP__HOST=127.0.0.1`.
   The example bind-all value exposes the listener to reachable interfaces;
   `/health`, `/ready`, and `/metrics` do not require a bearer token. Restrict
   those endpoints at the network or proxy boundary.
3. Run `./request-guard-mcp` on Linux/macOS or `./request-guard-mcp.exe` in
   PowerShell. Leave the process running. The default port is `8085`.
4. Check `http://127.0.0.1:8085/health`. Configure an HTTP POST MCP client for
   `http://127.0.0.1:8085/mcp` with `Authorization: Bearer <your token>`, then
   confirm `tools/list` includes `classify` and `explain`.

Use nonsecret request IDs. Published v0.1.5 can include a caller-supplied ID
in a tool-error warning; this bundle logs only the categorical tool error
code. This does not redact other server or backend diagnostics.

For HTTP clients, send `Content-Type: application/json` and
`Accept: application/json, text/event-stream` on POST. After initialization,
send `MCP-Protocol-Version: 2025-06-18`. A client notification or response
accepted over HTTP receives 202 with no body. An authenticated ordinary GET
to `/mcp` receives 405 because this server does not offer an SSE stream.

A custom WebSocket client can connect to `ws://127.0.0.1:8085/mcp` with
`Authorization: Bearer <your token>` on the HTTP/1 upgrade request, then send
JSON-RPC 2.0 messages as text frames. Use `wss://` through a trusted TLS
proxy for a remote client. This is this server's custom WebSocket transport,
not an SSE stream or HTTP/2 extended CONNECT. Browser WebSocket APIs cannot
set the upstream bearer header; the trusted proxy must authenticate the
browser and supply it, as described below.

For a remote client, use a trusted TLS endpoint in front of the server and
restrict who can reach it. Do not send the bearer token over plain HTTP across
an untrusted network. This bundle also offers process-local `--stdio`;
v0.1.4 did not. Neither this bundle nor v0.1.5 offers SSE GET.

For a local native installation, set the MCP client's command to the
absolute path of the extracted `request-guard-mcp` executable (or
`request-guard-mcp.exe` on Windows) and its arguments to `["--stdio"]`. The client
owns the child process and exchanges one JSON-RPC message per line over its
stdin/stdout; logs go to stderr. No TCP listener starts. Process access is
the trust boundary: `AUTH_TOKENS`, `MCP_ALLOWED_ORIGINS`,
`CACHE_SCOPE_HMAC_KEY`, `MCP__HOST`, and `MCP__PORT` do not secure or configure
the stdio channel. Keep the executable and client configuration
accessible only to trusted local users. Explicit environment variables and
`CONFIG_FILE` still configure optional backends; automatic `.env` discovery
is disabled in stdio mode. PostgreSQL is currently rejected in this mode
because its rows do not expire and each launch uses a fresh caller scope;
Redis entries retain their configured TTL. Requests are processed
sequentially and the transport has no session resumption or standalone SSE.
The optional Python SDK probe is **not in this archive**. To repeat it, check
out the [source commit recorded in the bundled README](README.md) in a
separate directory, install `mcp==2.3.0` in a disposable Python environment,
and run `scripts/python_sdk_stdio_smoke.py` there with `--binary` pointing to
this extracted executable and `--expected-version` set to the executable's
Cargo version (shown by an authenticated `model_info` call). A private
candidate archive label such as `v1.0.0-rc.N` is not the Cargo version.
Starting with v0.1.4, PostgreSQL TLS verification uses the operating system CA
store. For a private database CA, install it in that store or set
`sslrootcert=/path/to/ca.pem` in `MCP__POSTGRES__URL`. Use
`sslmode=verify-full` to verify both the certificate chain and hostname;
`sslmode=require` encrypts the connection but does not verify either. Minimal
container and Alpine hosts need a populated CA store unless `sslrootcert`
supplies the private CA. With `sslmode=verify-full`, an untrusted certificate
or mismatched hostname prevents server startup; the core tools do not become
available in that configuration. Published v0.1.3 predates the
native-root change.

The optional Redis integration in this bundle and published v0.1.5 accepts
plaintext `redis://` only. An attempted `rediss://` URL fails startup with a
TLS-feature error; it does not fall back to plaintext. A password in a
`redis://` URL authenticates the connection but does not encrypt the password
or traffic. Use Redis only across a trusted, isolated local/private link, or
terminate an independently secured tunnel at a loopback Redis endpoint. If
you cannot provide that boundary, leave Redis unconfigured; core
classification remains available without it. The Compose and Kubernetes
backend manifests are local demo configurations, not encrypted Redis examples.
For a production PostgreSQL server on a network, set
`sslmode=verify-full` and configure a trusted CA as described above; the
shipped in-cluster PostgreSQL URL example is local demo configuration.
For HTTP or WebSocket operation with PostgreSQL enabled, also configure a
stable, unique `CACHE_SCOPE_HMAC_KEY` of at least 32 bytes, distinct from
`AUTH_TOKENS`. Without it the server refuses to start, because caller-scoped
records must remain accessible after restart and across replicas. Keep this
key private and back it up under your deployment's secret-management policy.

When PostgreSQL is enabled, this bundle stores a reduced replay snapshot:
user agent, path, method, and whether the request supplied Accept
or Accept-Language headers. It discards header values, bodies, arbitrary
`extra`, IP, referrer, timestamp, request ID and TLS fingerprint/attestation
material before storing the request JSON. The stored response still contains
the request ID, original verdict and signals. Replay of an attested TLS fingerprint may differ because the
short-lived trusted provenance cannot be reconstructed. Paths and user agents
may still contain personal data; do not forward secrets in them. Published
v0.1.5 stores the full classify request, and upgrading does not rewrite older
rows. PostgreSQL has no automatic decision expiry. Set an operator retention
period appropriate to your data policy and schedule a purge, for example:

```sql
DELETE FROM mcp_decisions WHERE created_at < NOW() - INTERVAL '30 days';
```

Deleting decisions also deletes linked feedback through the schema's foreign
key cascade and removes those decisions from replay and historical reports.
Back up or export records you must retain before purging. To reduce older
full-payload rows without deleting their linked feedback, review and run
[`scripts/postgres_minimize_legacy.sql`](scripts/postgres_minimize_legacy.sql)
as a one-time operator migration, including rows with an old NULL caller
scope. It rewrites every decision row and generates WAL, so schedule a
maintenance window for large tables. For example, after configuring `psql`
connection credentials outside shell history:

```sh
psql -v ON_ERROR_STOP=1 -f scripts/postgres_minimize_legacy.sql
```

The migration preserves current non-attested replay signals, but old
attested-TLS decisions may already replay differently. Confirm the desired
retention period and purge older rows separately.
An upsert of the same request ID resets `created_at`, so the retention clock
starts again. Development main clears feedback when the stored replay inputs
or response change, but keeps feedback for an equivalent retry. A changed
decision needs a new label. Published v0.1.5 does not clear feedback on
replacement; use a fresh request ID for each distinct event. Existing stale
labels from older releases are not repaired automatically. Deletion does not
immediately erase old bytes from PostgreSQL
dead tuples, WAL, replicas or backups: arrange vacuum and backup/WAL expiry
under your data policy.
Starting with v0.1.4, MCP HTTP POST and WebSocket requests carrying `Origin`
must match an exact entry in `MCP_ALLOWED_ORIGINS`; for example,
`MCP_ALLOWED_ORIGINS=https://console.example`. List the public browser origin
when using a reverse proxy, including a nondefault port. Do not use wildcards,
paths, default ports (`:80`/`:443`), uppercase hosts, or the literal `null`.
For a cross-origin browser client, the trusted proxy must handle CORS preflights
and response headers; the server allowlist alone does not enable CORS.
Browser WebSocket clients also need a trusted proxy to authenticate the browser
and set the upstream bearer header, which the browser WebSocket API cannot set.
Requests without `Origin` remain available to
non-browser clients under the configured authentication policy. Published v0.1.3 does not
include this check; enforce browser-origin restrictions at the proxy for it.

The companion Agensi skill is installed separately. It provides agent
instructions, not the server binary or credentials, and is not a GitHub release
asset. This guide covers the bundled transport and backend setup; for the
repository's additional examples and deployment manifests, follow the exact
source-commit link in the bundled `README.md`.
