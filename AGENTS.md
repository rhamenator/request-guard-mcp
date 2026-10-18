# Request Guard work notes

- Preserve the inbound classifier and its existing MCP contracts while adding outbound behavior. New egress tools are opt-in.
- Treat network targets and response bodies as untrusted. Test SSRF, redirects, secrets, stream limits, and audit isolation with local fixtures. Never use live attack targets or print credentials.
- Reuse the existing Rust/Tokio, auth scope, and telemetry code. Search for an existing helper before adding a dependency. Keep tool output and audit records bounded and redacted.
- Run `cargo fmt --all` and focused tests after changes. Run the full suite once before release; repeat only when a specific regression risk remains.
- Keep the implementation status in `docs/egress-design/README.md` and the user-facing README truthful. An MCP tool cannot enforce requests routed through other tools or shell commands.
