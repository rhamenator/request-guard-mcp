# Container build timing follow-up

Issue #88 tracks multiarch container build time. GitHub-hosted runs around
v0.1.3 showed substantial overlap:

| Run | Ref | Build and Push Container job wall time |
| --- | --- | ---: |
| [39361627226](https://github.com/rhamenator/request-guard-mcp/actions/runs/39361627226) | v0.1.3 tag | 31m 25s |
| [39361614470](https://github.com/rhamenator/request-guard-mcp/actions/runs/39361614470) | main, same release period | 51m 45s |
| [39364390257](https://github.com/rhamenator/request-guard-mcp/actions/runs/39364390257) | later main | 51m 06s |
| [39370191954](https://github.com/rhamenator/request-guard-mcp/actions/runs/39370191954) | main, no server source changes | 18s |

These are whole-job wall times, not per-architecture compile times. The
current combined Buildx step does not expose reliable separate amd64/arm64
durations or cache-hit rates in the job summary. Its tag log contained seven
`CACHED` build lines, but that count is not a cache-hit percentage. The fast
later run shows useful cache reuse; it does not establish that cold release
builds are fast.

The container workflow now cancels an older run only when a new head of the
same pull request supersedes it. Main, manual, and tag runs are not cancelled.
This reduces duplicate PR builds without changing required container checks,
published architecture coverage, or release provenance. The larger
multiarch optimization remains open: instrument per-platform build time and
cache reuse, then compare a split native build/manifest assembly with the
current combined Buildx build before changing release publication.

## Native cold-build experiment

The manual `Container Cold Build Benchmark` workflow builds the Dockerfile
separately on GitHub's `ubuntu-24.04` amd64 and `ubuntu-24.04-arm` arm64
runners. It disables the BuildKit layer cache, loads each image only on its
own runner, verifies its architecture, runs a local container health smoke,
and records build-and-load seconds in each job summary. It does not log in to
GHCR, push an image, or change the
required container check. The benchmark's `no-cache` setting makes layer
cache hits zero by design; it does not measure warm-cache behavior. Base-image
pulls, package registry latency, and runner variation still affect elapsed
time. The Dockerfile has no cross-compilation stage, so on these checked
native runners its Rust build uses the runner architecture.

The v0.1.3 combined tag job's 31m 25s is context, not a controlled baseline:
it may have used cache and included setup, registry push, and attestations at
a different commit. A split publication would take at least the slower of the
two native jobs plus manifest assembly and verification. Repeat the benchmark
and compare a no-cache combined build at the same commit before claiming a
material improvement. If native builds then show a benefit, a separate
PR can split publication into two architecture-specific builds and a manifest
assembly job, with digest and client checks before the next tag. GitHub lists
`ubuntu-24.04-arm` as a standard hosted runner for public repositories, and
Docker documents the distributed build pattern:
[GitHub runner reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax),
[Docker multi-platform CI guide](https://docs.docker.com/build/ci/github-actions/multi-platform/).

The same manual workflow also runs a controlled three-way OCI export at one
commit: native amd64, native arm64, and the combined amd64+arm64 build on
amd64. All three use `no-cache: true`, the same Dockerfile, and the same OCI
archive exporter. The job checks the archive index for exactly the expected
platforms. It publishes and uploads nothing. Compare the combined elapsed
time against `max(native amd64, native arm64)`; that approximates the build
portion of a split release, while manifest assembly, registry push, and
attestations still need a separate end-to-end check. The earlier native
build-and-load jobs remain for image health smoke and historical comparison.

At commit `67e4ed4`, [run 39397571246](https://github.com/rhamenator/request-guard-mcp/actions/runs/39397571246)
passed the three no-cache OCI exports: native amd64 205 seconds, native arm64
184 seconds, and combined QEMU amd64+arm64 1,812 seconds. Each archive's
platform set was checked. This single sample motivates splitting publication;
it does not include GHCR pushes, digest assembly, or attestations and is not
an end-to-end release-time measurement.

## Split publication verification

The publication workflow builds each platform on its matching hosted runner
and pushes it by immutable digest. It uploads only one validated digest per
architecture to the workflow artifact store. The final job reads and verifies
both source manifests, assembles the multiarch index from those exact digests,
checks that the index contains linux/amd64 and linux/arm64 with a provenance
attestation linked to each platform digest, and checks that
every release tag resolves to the same index digest. PRs retain the existing
`Build and Push Container` required check on amd64, without publishing.
Platform-specific cache scopes prevent the two native jobs from overwriting
one another's cache. A main-branch run and the next experimental tag must
prove the complete path before issue #88 can close; compare whole-job elapsed
time with the earlier release runs, including push and manifest assembly.
