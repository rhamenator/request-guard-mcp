---
name: request-guard-mcp
description: Use a connected request-guard-mcp server to classify observed HTTP request metadata, explain its verdicts, and inspect its available abuse signals. Applies to this MCP server, not to deploying the separate AI Scraping Defense products or guarding agent outbound fetches.
---

# Request Guard MCP

Connect the server using the [Request Guard repository](https://github.com/rhamenator/request-guard-mcp) instructions. Confirm `tools/list` includes `classify` and `explain` before using this skill. The AI Scraping Defense projects may use their own detection logic, this server, another MCP server, or no MCP server; do not change that choice on the user's behalf.

## When and how

- For an observed inbound website or API request that needs a risk assessment, call `classify` with only relevant metadata, such as `ip`, `user_agent`, `method`, `path`, and selected headers. Avoid sending request bodies, cookies, authorization headers, and personal data unless the task requires them and the user has authorized that transfer.
- For a batch of observed requests, call `batch_classify` if available. To explain a specific result, call `explain` with the classification returned by the server. Use `model_info` and `health` to check capability and service status before relying on an optional backend tool.
- Use enrichment, reputation, canary, replay, drift, or calibration tools only when the corresponding backend is configured and the user's task calls for that evidence. Report an unavailable backend as unavailable, not as a clean signal.

Record the returned request ID, verdict, confidence, and contributing signals. TLS fingerprints supplied by an ordinary caller are unverified without the server's attestation path; never invent that provenance. The result supports a site owner's policy decision. A website must explicitly send requests to the classifier and enforce its own response; this skill cannot route live traffic or block a visitor by itself.
