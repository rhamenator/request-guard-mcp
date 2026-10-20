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
