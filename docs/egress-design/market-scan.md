# Security listings reviewed on Agensi

Reviewed 2026-10-18. This is product research, not a requirement to copy another listing or to publish this branch. Agensi's current pages predominantly describe **skills**; this repository is an MCP server with a companion draft skill. The listings' technical claims have not been independently verified.

| Listing | Advertised scope | Useful comparison |
| --- | --- | --- |
| [AgentShield](https://www.agensi.io/skills/agentshield-ai-skill-mcp-security-scanner) | Static scanning of MCP/skill assets, permissions, secrets, injection, and dependencies | Document exactly what a scan does and show rule IDs, evidence, permissions, and limitations. Request Guard's runtime fetch path serves a different purpose. |
| [VibeRuntime](https://www.agensi.io/skills/viberuntime-autonomous-ai-execution-sandbox-guard) | Shell command checks, network allowlists, audit reports | Explain the actual interception boundary. A skill cannot make all agent shell/network calls pass through Request Guard; only `guarded_fetch` calls are covered. |
| [Prompt Injection Security Gate](https://www.agensi.io/skills/prompt-injection-agent-security-gate-block-hidden-instructions-before-your-agent-acts) | Inspection of untrusted text already held by an agent | Preserve source provenance and state that heuristics cannot prove fetched content safe. |
| [Rust Guard Auditor](https://www.agensi.io/skills/rust-guard-auditor-check-your-rust-runtime-guard-actually) | Static coverage checks for Rust process execution | Add client integration tests that show requests reach `guarded_fetch`, plus host controls for unguarded routes. |

## Gaps to close before a public security claim

1. Publish copyable, tested local client configurations for Codex, Claude Code, and Cursor. Keep tokens out of examples; document exact network, filesystem, and environment permissions.
2. Finish conformance testing for every advertised MCP transport and capability. The current HTTP POST endpoint is not full Streamable HTTP.
3. Add controlled DNS and HTTP fixtures for rebinding, mixed records, redirects, slow streams, encoded responses, and concurrency. Current unit tests cover policy decisions, but do not prove all connection behavior.
4. Move beyond regex-only HTML inspection or keep the conservative quarantine policy and its false positives prominent. Test against hidden CSS fixtures from the scraping-defense projects.
5. Provide versioned rule documentation, stable JSON output examples, a threat model, and a clear explanation of how users can connect this server independently of the `ai-scraping-defense` projects.

Agensi says its [security review](https://www.agensi.io/security) checks skill structure, file types, dangerous commands, secrets, environment harvesting, network access, obfuscation, and injection. Its [creator guide](https://www.agensi.io/learn/how-to-sell-skills-on-agensi) describes a ZIP containing a `SKILL.md` for a skill listing. Those are packaging considerations for a future companion skill, not proof that the MCP server passes a security audit.
