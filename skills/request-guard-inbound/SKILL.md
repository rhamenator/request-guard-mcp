---
name: request-guard-inbound
description: Classify and explain inbound website or API request abuse with a connected request-guard-mcp server. Use when reviewing bot or scraper traffic, tuning inbound defenses, or integrating this classifier; not for outbound HTTP or shell safety.
---

# Request Guard inbound

Use this skill only when `request-guard-mcp` is connected. Install and configure the server from [its repository](https://github.com/rhamenator/request-guard-mcp); verify `tools/list` includes `classify` and `explain`. The MCP connection is optional for the `ai-scraping-defense` projects and for other web stacks.

## Choose the tool

- For one observed inbound HTTP request, call `classify` with the available request metadata (`ip`, `user_agent`, `method`, `path`, and relevant headers). Omit bodies and secrets unless essential and authorized. Record the returned `request_id`, verdict, confidence, and contributing signals.
- For many observed requests, use `batch_classify` when it is enabled. For a decision a site owner needs to understand, call `explain` with the classification result. Use `score_breakdown` or `model_info` when checking scoring or tool availability.
- Use `enrich_ip`, `threat_lookup`, canary, replay, drift, or calibration tools only when their documented backing service is configured and the task needs that evidence. An unavailable integration is not a clean threat result.

The server treats supplied TLS fingerprints as unverified unless a trusted producer supplies valid attestation. Do not invent or mark TLS provenance as verified. Treat a classification as evidence for the site's policy, not as a command to block an IP automatically. The website or API must explicitly route traffic to the server and decide how to enforce a verdict; installing this skill does neither.
