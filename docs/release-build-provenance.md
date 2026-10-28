# Native release build inputs and provenance

All five native Release lanes use Rust 1.99.1, matching the pinned repository
toolchain and blocking CI checks. Each packaged binary reports its full source
commit, Rust version, and UTC runner build date through the `model_info` MCP
tool; the workflow checks those fields in the extracted executable. The build
date and hosted runner inputs do not make the archives bit-for-bit reproducible.

The `linux-x64-musl` release lane uses Ubuntu 24.04, Rust 1.99.1, and Ubuntu's
`musl`, `musl-dev`, and `musl-tools` packages at `1.2.4-2`. It records the
installed package, Rust, and GCC versions in the workflow summary. The Alpine
smoke runs `alpine:3.24.2` by the Docker Official Image index digest
`sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6`.
Cargo dependencies remain pinned by `Cargo.lock`.
The workflow sets `RUSTUP_TOOLCHAIN=1.99.1` explicitly in every lane and asserts
the active compiler and target before building. The musl lane additionally
records the installed linker and package versions.

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
it installs test tools in a disposable container only. The musl lane requires
an ELF PIE with no interpreter or shared-library `NEEDED` entry. Its Alpine
smoke checks that a nonempty, bounded server log does not expose a synthetic
bearer token or classification request marker; the log is not emitted to CI
output. The probe does not cover optional backend or TLS collector failure
logs yet.
The release lane also runs a Redis lookup probe inside disposable Alpine:
seeded lookup, backend stop with a deterministic `-502` error, core classify
during outage, and lookup recovery after restart. Both services use container
loopback ports only; no test credentials or integration logs are published.
Python and Redis are installed in that disposable test image from Alpine's
versioned 3.24 repositories; those test package revisions are not pinned.
Another disposable Alpine probe starts PostgreSQL on container loopback,
checks persisted classification and replay before/after an immediate backend
stop, requires deterministic `-502` responses during outage, checks the
decision row survived the database restart, and confirms core MCP ping
remains available. It inspects the bounded private MCP server log for
synthetic tokens and cache-scope keys. PostgreSQL and Python test package
revisions come from the versioned Alpine repository and are not pinned.
Private branch candidates run the same build and verification steps without
creating a GitHub release or a public artifact attestation. Tagged builds
download the five verified archives in a separate job, attest their immutable
digests with GitHub's signed release-workflow provenance, and verify that the
attestations bind each archive to the repository, tag ref, and source commit
before creating a release. The build jobs have no OIDC or attestation-write
permission. An archive sidecar is a same-workflow corruption check, not a
signature. For v1+ tags, the workflow creates a draft GitHub Release. Verify
the exact tagged assets and attestations before publishing that draft. Tagged
native builds do not restore cached Rust build outputs. Published v0.1.5
predates native attestations.

"Private" describes publication status, not confidentiality: signed-in readers
with access to this public repository can download the Actions candidate
archives and sidecars; new candidate and tagged runs retain them for up to
seven days. Candidate artifacts must contain no credentials or sensitive lab
evidence. Reviewers who need an expired candidate should rerun the private
workflow from the exact source commit and reverify the new archive digests.
Build timestamps and hosted runner inputs mean those digests need not match the
expired candidate's digests.

This pins the Rust toolchain and main musl-specific inputs; hosted runner
images, the Ubuntu apt repository, and platform SDKs can still change. Review
the workflow summary, archive hashes and tagged attestations for every release.

## Container image input policy

`docker/Dockerfile` pins the multiarchitecture Rust 1.99.1 builder and Debian
Bookworm runtime base image indexes by SHA-256. The Docker build asserts the
Bookworm codename and compiler version, does not run a blanket `apt-get
upgrade`, and saves the resolved builder/runtime package inventories and
toolchain versions inside each image. Dependabot proposes base-image refreshes
for review. The native amd64 and arm64 container workflows build and smoke
each immutable platform digest before assembling a multiarchitecture index.

**Decision for issue #165:** retain live Debian package resolution for
`apt-get update && apt-get install` rather than pinning an apt snapshot. This
keeps the Dockerfile simple and allows a reviewed rebuild to pick up current
Bookworm package fixes, but it means that the same source commit can resolve
different package versions later. The embedded UTC build date and other build
inputs also prevent a bit-for-bit reproducibility claim. A base-image digest
alone does not pin installed apt packages. We therefore identify and qualify
**the exact published image digest**, not an assumed reproducible rebuild.

For the immutable v1.0.0 source commit
`22a199a8cd0f7faf5f3e4493dc770e79d859680b`, the
[tagged container workflow](https://github.com/rhamenator/request-guard-mcp/actions/runs/40596296683)
passed native amd64 and arm64 client checks and published index
`sha256:8c3f2f4d72b673d1c1f103fc374e15f049945d1af75c8c2ed6f66e02347bca14`.
The separate [published-index qualification](https://github.com/rhamenator/request-guard-mcp/actions/runs/40597201881)
passed both architectures against that same index. These results qualify
those observed bytes and architectures; they do not prove future rebuilds
identical or automatically qualify a later release. Review each later image's
package inventories, platform digests, source-bound attestations, scanner
results, and native client tests before publishing its tag.
