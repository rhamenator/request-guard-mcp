# npm release package

The GitHub Packages entry for `request-guard-mcp` is a container image. The npm
package is a separate installation option for the official native release.
The stable [1.0.0 package](https://www.npmjs.com/package/request-guard-mcp/v/1.0.0)
is assembled from the five final tagged native archives and their checksum
sidecars. A clean tarball install and a fresh public-registry install passed
MCP Inspector authentication, initialization, discovery of 23 tools,
`classify`, `explain`, and bounded stdio smoke on Linux x64. The exact tagged
assets, source identity, and release gate are recorded in [issue #125](https://github.com/rhamenator/request-guard-mcp/issues/125).
A later [five-platform GitHub qualification](https://github.com/rhamenator/request-guard-mcp/actions/runs/40632345730)
passed a clean global public-registry install and uninstall on Linux x64 glibc,
Linux x64 musl/Alpine, Windows x64, macOS Intel, and macOS Apple Silicon.
Every lane compared the registry tarball with its SHA-512 integrity, matched
the installed native binary byte-for-byte with its checksum-verified tagged
release archive, and ran the installed command through bounded stdio and the
pinned official MCP Inspector for authenticated initialization, tool discovery,
`classify`, and `explain`. It checked that the global package and shims were
removed. This run used ephemeral GitHub runners and a disposable Alpine
container; it did not test OS signing/notarization prompts or an upgrade path.
Each later candidate needs its own exact-artifact qualification.
The experimental [0.1.5 package](https://www.npmjs.com/package/request-guard-mcp/v/0.1.5)
remains available for existing installations.

## Install and connect

Run `npm install -g request-guard-mcp@1.0.0`. Set a unique random
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

The published v1.0.0 package was built from five native release archives and
their SHA-256 sidecars, including Linux x64 musl. The tagged npm packaging
step verified all ten checksums and extracted only the expected binary from
each archive. The public nine-file tarball has no install scripts or runtime
dependencies; installation does not download executable code. The small Node launcher selects the bundled
binary and forwards arguments, environment, stdio, and termination signals.
On Linux v1.0.0, HTTP mode gives the native child a private stdin pipe.
If the launcher is forcibly killed, closing that pipe starts a bounded server
drain. Published v0.1.5 lacks this safeguard; when forcibly killing its npm
launcher in HTTP mode, also stop the native child or the whole process group
so the listener does not remain active. Forced-kill child lifetime on macOS
and Windows has not been qualified by this Linux probe.
The v1.0.0 launcher selects the musl binary on Alpine and the glibc binary
on glibc Linux hosts. The exact tagged musl native archive passed the pinned
Alpine MCP Inspector smoke; the public npm launcher passed Inspector on glibc
Linux x64 during release-day qualification. The later five-platform run above
also exercised the public npm launcher on Alpine, macOS, and Windows.

For a trusted local stdio client, configure its command as `request-guard-mcp`
and arguments as `["--stdio"]`. The launching process is the trust boundary:
stdio has no HTTP bearer authentication, no listener, and no PostgreSQL
integration. A clean public-registry 1.0.0 install passed the bounded stdio
smoke. The older 0.1.4 package does not support stdio.

For each later approved npm release, after its native assets are published:

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
