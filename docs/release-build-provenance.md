# Alpine release build inputs

The `linux-x64-musl` release lane uses Ubuntu 24.04, Rust 1.99.1, and Ubuntu's
`musl`, `musl-dev`, and `musl-tools` packages at `1.2.4-2`. It records the
installed package, Rust, and GCC versions in the workflow summary. The Alpine
smoke runs `alpine:3.24.2` by the Docker Official Image index digest
`sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6`.
Cargo dependencies remain pinned by `Cargo.lock`.
The musl job sets `RUSTUP_TOOLCHAIN=1.99.1` explicitly because the repository's
`rust-toolchain.toml` otherwise selects a moving `stable` channel even after
the workflow installs the pinned toolchain. CI asserts that the musl target is
installed for the active compiler before building.

Before a future build-input refresh, verify the new Ubuntu package versions
against [Ubuntu's package index](https://packages.ubuntu.com/noble/musl-tools),
inspect the Alpine digest with `docker buildx imagetools inspect
docker.io/library/alpine:3.24.2`, and review the Docker Official Image source
revision and platform manifests. Change the pins in the release workflow and
`scripts/smoke_alpine_musl.py` together on a PR. A missing pinned package or
image fails the build rather than silently substituting a newer input.

The workflow verifies each archive's SHA-256 sidecar, extracts into a new
directory, and compares the extracted executable with the staging binary.
MCP Inspector and the Alpine smoke run that extracted executable. The musl
lane additionally runs the pinned official MCP Inspector inside the pinned
Alpine image against the extracted executable. This checks Alpine's Node,
Python, musl, and HTTP client path as part of private candidates and tags;
it installs test tools in a disposable container only. The musl lane also
requires an ELF PIE with no interpreter or shared-library `NEEDED` entry.
Private branch candidates run the same build and verification steps without
creating a GitHub release.

This pins the main musl-specific inputs; hosted runner images, the Ubuntu apt
repository, and the remaining platform toolchains can still change. Review
the workflow summary and archive hashes for every release.
