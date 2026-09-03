# Contributing

Thank you for improving Request Guard MCP. Small, focused changes with clear validation are the easiest to review and maintain.

## Choose the Right Channel

- Use the structured [issue forms](https://github.com/rhamenator/request-guard-mcp/issues/new/choose) for confirmed bugs, feature proposals, documentation problems, and support questions.
- Read [SUPPORT.md](SUPPORT.md) before requesting help.
- Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do not open a public issue for them.
- Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) in all project spaces.

Search existing issues and pull requests before opening a new one. For larger or compatibility-sensitive changes, open an issue first so the design can be discussed before substantial implementation work.

## Development

Use the declared minimum supported Rust version and current stable Rust, and keep changes scoped. Add tests for behavioral changes and update the README, docs, schemas, deployment examples, or configuration references when they are affected.

Run the full local validation suite before submitting a pull request:

```shell
make ci
```

The equivalent individual checks are:

```shell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo audit
cargo deny check
```

If a check cannot be run locally, explain why in the pull request and report what you ran instead.

## Dependencies and Rust Compatibility

- Add a direct dependency only when the project uses it; remove unused direct dependencies.
- Keep `Cargo.lock` committed for reproducible builds. Compatible updates are accepted only after the full CI suite passes.
- Treat major-version updates and changes that raise a dependency's Rust requirement as compatibility changes. State the impact in the pull request and update `rust-version` only through an explicit review decision.
- CI validates both the declared MSRV and current stable Rust. Do not merge an update that breaks either supported toolchain unless the project has explicitly changed its MSRV policy.

## Pull Requests

- Create a focused branch from `main` and keep commits concise and intentional.
- Complete the pull request template, link related issues, and list exact validation commands and results.
- Call out changes to MCP behavior, tool schemas, APIs, authentication, configuration, persistence, metrics, performance, or deployment.
- Never commit secrets, credentials, private request content, production data, or sensitive infrastructure details.
- Address review feedback and keep the branch current until required checks pass.

By contributing, you agree that your contribution is licensed under the repository's license.
