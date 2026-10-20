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
own runner, verifies its architecture, and records build-and-load seconds in
each job summary. It does not log in to GHCR, push an image, or change the
required container check. The benchmark's `no-cache` setting makes layer
cache hits zero by design; it does not measure warm-cache behavior.

Compare the two native durations with the 31m 25s v0.1.3 combined tag job
above, accounting for checkout, setup, registry push, and source differences.
If arm64 native compilation materially reduces cold elapsed time, a separate
PR can split publication into two architecture-specific builds and a manifest
assembly job, with digest and client checks before the next tag. GitHub lists
`ubuntu-24.04-arm` as a standard hosted runner for public repositories, and
Docker documents the distributed build pattern:
[GitHub runner reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax),
[Docker multi-platform CI guide](https://docs.docker.com/build/ci/github-actions/multi-platform/).
