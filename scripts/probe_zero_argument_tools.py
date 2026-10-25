#!/usr/bin/env python3
"""Check packaged health and model_info argument contracts over MCP stdio."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}]
    for tool in ("health", "model_info"):
        for payload in ({}, {"unknwon": "synthetic"}):
            requests.append({"jsonrpc": "2.0", "id": len(requests) + 1,
                             "method": "tools/call", "params": {"name": "validate_payload",
                                                                 "arguments": {"tool": tool,
                                                                               "payload": payload}}})
            requests.append({"jsonrpc": "2.0", "id": len(requests) + 1,
                             "method": "tools/call", "params": {"name": tool,
                                                                 "arguments": payload}})
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}}
    with tempfile.TemporaryDirectory(prefix="rg-zero-argument-") as cwd:
        env["HOME"] = cwd
        result = subprocess.run([str(binary), "--stdio"],
                                input=b"".join((json.dumps(req) + "\n").encode()
                                               for req in requests), cwd=cwd, env=env,
                                capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, len(requests) + 1)):
        raise AssertionError("unexpected stdio response order")
    schemas = {tool["name"]: tool["inputSchema"] for tool in responses[0]["result"]["tools"]}
    for tool, start in (("health", 1), ("model_info", 5)):
        schema = schemas[tool]
        if schema.get("properties") != {} or schema.get("additionalProperties") is not False:
            raise AssertionError(f"{tool} is not advertised as zero-argument")
        if responses[start]["result"]["structuredContent"]["valid"] is not True:
            raise AssertionError(f"{tool} validator rejected empty arguments")
        if "structuredContent" not in responses[start + 1].get("result", {}):
            raise AssertionError(f"{tool} rejected empty arguments")
        if responses[start + 2]["result"]["structuredContent"]["valid"] is not False:
            raise AssertionError(f"{tool} validator accepted unknown argument")
        error = responses[start + 3].get("error", {})
        if (error.get("code"), error.get("message")) != (-400, "INVALID_REQUEST"):
            raise AssertionError(f"{tool} callable accepted unknown argument")
    print("PASS packaged zero-argument health and model_info contracts")


if __name__ == "__main__":
    main()
