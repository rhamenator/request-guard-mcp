# npm release package

The GitHub Packages entry for `request-guard-mcp` is a container image. The npm
package is a separate installation option for the official native release.
The experimental [0.1.4 package](https://www.npmjs.com/package/request-guard-mcp/v/0.1.4)
is published. A fresh registry install with an empty npm cache
passed Inspector authentication, initialization, listing 23 tools,
`classify`, and `explain` on Linux x64. This is an experimental release;
the adversarial production-readiness gate remains open.
The v0.1.4 package was assembled from all five final public native release
archives and their checksum sidecars. Both a clean local tarball install and a
fresh public-registry install passed MCP Inspector authentication,
initialization, tool listing, `classify`, and `explain`.

## Install and connect

Run `npm install -g request-guard-mcp@0.1.4`. Set a unique random
`AUTH_TOKENS` bearer token of at least 32 characters and bind locally before
starting the globally installed command. On Linux/macOS:

```bash
export AUTH_TOKENS='<your-unique-random-token-at-least-32-characters>'
export MCP__HOST=127.0.0.1
request-guard-mcp
```

On Windows PowerShell:

```powershell
$env:AUTH_TOKENS = '<your-unique-random-token-at-least-32-characters>'
$env:MCP__HOST = '127.0.0.1'
request-guard-mcp
```

Leave the server running. Check `http://127.0.0.1:8085/health`, then point an
HTTP POST MCP client at `http://127.0.0.1:8085/mcp` with
`Authorization: Bearer <your token>`. Confirm `tools/list` includes `classify`
and `explain`. Redis and PostgreSQL are optional for these core tools. The
npm package does not include `.env.example`; [INSTALL.md](../INSTALL.md)
describes the separate native release bundle. For remote access, put a
trusted TLS endpoint in front of the server and restrict who can reach it.

The published v0.1.4 package was built from five native release archives and
their SHA-256 sidecars, including Linux x64 musl. It verifies every checksum and extracts only the
expected binary from each archive. Installation does not run a `postinstall` script
or download executable code. The small Node launcher selects the bundled
binary and forwards arguments, environment, stdio, and termination signals.
The published 0.1.4 launcher selects the musl binary on Alpine and the glibc
binary on glibc Linux hosts. A clean install on Alpine and on glibc Linux passed
the official five-check MCP Inspector smoke test.

For a future approved npm release, after its native assets are published:

1. Download all ten archive and `.sha256` assets for the **same** tag into a
   private working directory. Do not include the local Agensi skill ZIP.
2. Run `python3 scripts/package_npm.py --name request-guard-mcp --version
   <matching-tag> --assets <asset-directory> --output <new-package-directory>`.
3. Run `npm pack --dry-run --json` in the generated directory and inspect its
   file list. Install the resulting tarball into a clean temporary npm prefix,
   start the packaged command with a fresh bearer token, and repeat the HTTP
   MCP Inspector smoke test against that installed command. For v0.1.5 and
   later, also run `python3 scripts/stdio_release_smoke.py --binary <installed-command>
   --expected-version <version>` against the clean install. Verify the npm
   launcher forwards the caller's `--stdio` flag and keeps protocol output free
   of diagnostics.
4. Confirm the npm account owns the intended package name, configure npm
   publishing credentials or trusted publishing, and publish the matching
   version only after its release is approved. Verify the published tarball
   and command from a fresh registry install. Do not publish an RC as `latest`.

For v0.1.4, the release smoke also checks PostgreSQL TLS trust on the packaged
Alpine binary with `sslmode=verify-full`: an explicit trusted CA and an
installed OS CA work; an unknown issuer or hostname mismatch prevents startup
when PostgreSQL is configured in that mode.
See [the release evidence](releases/v0.1.4-postgres-tls-evidence.md).

The generated package contains the GPL-3.0-or-later license, a short npm setup
guide, the launcher, and the five binaries. It contains no credentials, `.env`,
Agensi skill ZIP, release build cache, or runtime npm dependencies.
