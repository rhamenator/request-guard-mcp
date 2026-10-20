# Install Request Guard MCP from a release bundle

Download the archive for your operating system and CPU from the GitHub release,
along with its matching `.sha256` file. Verify the archive before extracting it:

The published v0.1.2 Linux x64 archive requires glibc. Alpine/musl support is
under private qualification for a later release; do not use the glibc archive
on Alpine. Check the release assets for a separately labeled musl archive only
after that support is published.

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

For a remote client, use a trusted TLS endpoint in front of the server and
restrict who can reach it. Do not send the bearer token over plain HTTP across
an untrusted network. The server does not offer stdio or SSE GET transport.

The companion Agensi skill is installed separately. It provides agent
instructions, not the server binary or credentials, and is not a GitHub release
asset. See the bundled `README.md` for client examples and optional backends.
