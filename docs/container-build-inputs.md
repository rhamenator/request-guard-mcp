# Container build inputs

`docker/Dockerfile` pins the multi-architecture OCI index for the Rust 1.99.1
builder and Debian Bookworm runtime. The private qualification workflow checks
both indexes for amd64 and arm64 before building. The builder asserts the
expected `rustc` version. The final image includes package inventories at
`/usr/share/request-guard-mcp/{builder,runtime}-packages.txt` and
`/usr/share/request-guard-mcp/toolchain.txt`. Each private native-runner job
stores copies as a 14-day artifact and records their SHA256 hashes and local
image ID in its step summary. Those copies describe only that private build.
The tag publication workflow separately extracts inventories from each exact
published platform digest and retains them for 14 days. The runtime stage
does not run an unbounded `apt-get upgrade`.

These changes fix the base-image references for a given Dockerfile revision;
they do **not** make the image bit-for-bit reproducible. `apt-get update` and
package installation still resolve against the current Debian repository,
and Cargo's locked source builds and image metadata can depend on build time
and runner details. For a release, record the Git commit, both base index
digests, package inventories and toolchain, each resulting platform digest,
the assembled index digest and attestations, then test the exact published digests. Issue
[#165](https://github.com/rhamenator/request-guard-mcp/issues/165) tracks the
remaining package snapshot decision.

Dependabot checks the `/docker` Dockerfile weekly for base updates, which
still require review and CI. Review the pinned Debian image and security
findings before each release and refresh it when fixes are needed. The normal
Security Scan workflow emits Trivy SARIF findings but does not automatically
block on every finding; the maintainer must inspect that report. To update the
bases, select a reviewed Rust patch release and Debian image, inspect each
index with `docker buildx imagetools inspect`, update the two
Dockerfile digests, and run the native amd64 and arm64 client/resource workflow.
Check the resulting inventories and security scan before merging. Keep the
stable-tag approval gate in place; a private candidate run must not publish
an image.
