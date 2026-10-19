# npm release package

The GitHub Packages entry for `request-guard-mcp` is a container image. The npm
package is a separate installation option for the official native release.
The experimental [0.1.1 package](https://www.npmjs.com/package/request-guard-mcp/v/0.1.1)
is published. Install it with `npm install -g request-guard-mcp@0.1.1`, configure
`AUTH_TOKENS`, and run `request-guard-mcp`; follow [INSTALL.md](../INSTALL.md)
to connect an MCP client. A fresh registry install with an empty npm cache
passed Inspector authentication, initialization, listing 23 tools,
`classify`, and `explain` on Linux x64. This is an experimental release;
the adversarial production-readiness gate remains open.

The package builder uses only the four native release archives and their
SHA-256 sidecars. It verifies every checksum, extracts only the expected
binary from each archive, and produces one dependency-free npm package with
all four supported platforms. Installation does not run a `postinstall` script
or download executable code. The small Node launcher selects the bundled
binary and forwards arguments, environment, stdio, and termination signals.
The Linux x64 binary requires glibc; musl-based distributions such as Alpine
are rejected with an explicit launcher error.

For a future approved npm release, after its native assets are published:

1. Download all eight archive and `.sha256` assets for the **same** tag into a
   private working directory. Do not include the local Agensi skill ZIP.
2. Run `python3 scripts/package_npm.py --name request-guard-mcp --version
   <matching-tag> --assets <asset-directory> --output <new-package-directory>`.
3. Run `npm pack --dry-run --json` in the generated directory and inspect its
   file list. Install the resulting tarball into a clean temporary npm prefix,
   start the packaged command with a fresh bearer token, and repeat the HTTP
   MCP Inspector smoke test against that installed command.
4. Confirm the npm account owns the intended package name, configure npm
   publishing credentials or trusted publishing, and publish the matching
   version only after its release is approved. Verify the published tarball
   and command from a fresh registry install. Do not publish an RC as `latest`.

The generated package contains the GPL-3.0-or-later license, a short npm setup
guide, the launcher, and the four binaries. It contains no credentials, `.env`,
Agensi skill ZIP, release build cache, or runtime npm dependencies.
