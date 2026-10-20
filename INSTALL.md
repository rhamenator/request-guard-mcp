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

Extract the archive, then work inside its `request-guard-mcp-<version>-<platform>`
folder. The server binary is already built; Rust, Cargo, Redis, PostgreSQL, and
MaxMind data are not needed for the core `classify` and `explain` tools.

1. Copy `.env.example` to `.env` (`cp .env.example .env` on Linux/macOS, or
   `Copy-Item .env.example .env` in PowerShell).
2. Replace `AUTH_TOKENS=replace_me_with_a_strong_token` in `.env` with a unique,
   randomly generated token of at least 32 characters. Keep `.env` private. For
   local-only use, change `MCP__HOST=0.0.0.0` to `MCP__HOST=127.0.0.1`.
3. Run `./request-guard-mcp` on Linux/macOS or `./request-guard-mcp.exe` in
   PowerShell. Leave the process running. The default port is `8085`.
4. Check `http://127.0.0.1:8085/health`. Configure an HTTP POST MCP client for
   `http://127.0.0.1:8085/mcp` with `Authorization: Bearer <your token>`, then
   confirm `tools/list` includes `classify` and `explain`.

For v0.1.4 HTTP clients, send `Content-Type: application/json` and
`Accept: application/json, text/event-stream` on POST. After initialization,
send `MCP-Protocol-Version: 2025-06-18`. A client notification or response
accepted over HTTP receives 202 with no body. An authenticated ordinary GET
to `/mcp` receives 405 because this server does not offer an SSE stream.

For a remote client, use a trusted TLS endpoint in front of the server and
restrict who can reach it. Do not send the bearer token over plain HTTP across
an untrusted network. The server does not offer stdio or SSE GET transport.
Starting with v0.1.4, PostgreSQL TLS verification uses the operating system CA
store. For a private database CA, install it in that store or set
`sslrootcert=/path/to/ca.pem` in `MCP__POSTGRES__URL`. Use
`sslmode=verify-full` to verify both the certificate chain and hostname;
`sslmode=require` encrypts the connection but does not verify either. Minimal
container and Alpine hosts need a populated CA store unless `sslrootcert`
supplies the private CA. A configured PostgreSQL connection with an untrusted
certificate or mismatched hostname prevents server startup; the core tools do
not become available in that configuration. Published v0.1.3 predates the
native-root change.
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
asset. See the bundled `README.md` for client examples and optional backends.
