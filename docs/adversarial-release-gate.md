# Adversarial release gate

Stable releases require a repeatable adversarial run against the packaged server's actual HTTP and WebSocket interfaces in an authorized lab. Record the tested commit and binary digest, configuration with secrets redacted, exact commands, tool versions, expected and observed outcomes, resource measurements, fixes, and residual limits. A passing unit suite or vulnerability scan alone does not satisfy this gate.

At minimum, exercise authentication boundaries, malformed JSON-RPC and MCP frames, invalid and oversized inputs, prompt-injection text treated as request data, bot-evasion variations, concurrency and slow clients, backend failure and recovery, and logging of sensitive fields. Use Kali and Ubuntu lab VMs when available; scope scanners to the owned test endpoint, record their request counts, and bound runtime and rate to preserve shared host responsiveness. Confirm each exploit or anomaly with a regression test, rerun the affected probe, then rerun the full gate. Reconcile independent Claude Code and Codex reviews with the observed runtime results and document remaining limits before a release.

The stdlib-only `scripts/adversarial_probe.py` is a first HTTP smoke subset. Start a lab server with a temporary token of at least 32 characters, then run:

```bash
python3 scripts/adversarial_probe.py --url http://LAB_HOST:8085 --token "$LAB_TOKEN" \
  --max-request-bytes 1048576
```

Set `--max-request-bytes` to the server's configured `MCP__LIMITS__MAX_REQUEST_BYTES`. The probe refuses to follow redirects, so the bearer token stays scoped to the explicitly named lab endpoint. Do not put the token in committed files or published logs. The probe prints no token. This subset does not validate WebSocket framing, sustained exhaustion, backend failures, or complete MCP interoperability; those cases need separate evidence before release.
