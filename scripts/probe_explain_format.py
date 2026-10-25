#!/usr/bin/env python3
"""Verify the packaged explain tool only advertises and accepts JSON output."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    classification = {"request_id": "synthetic-explain-format", "path": "/admin"}
    valid = {"classification": classification, "format": "json"}
    bad = [
        {"classification": classification, "format": "html"},
        {"classification": classification, "format": None},
        {"classification": classification, "fomat": "json"},
    ]
    calls = [("explain", {"classification": classification}), ("explain", valid)]
    for payload in bad:
        calls += [("explain", payload),
                  ("validate_payload", {"tool": "explain", "payload": payload})]
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}]
    requests += [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
                  "params": {"name": name, "arguments": payload}}
                 for i, (name, payload) in enumerate(calls, 2)]
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}}
    with tempfile.TemporaryDirectory(prefix="rg-explain-format-") as cwd:
        env["HOME"] = cwd
        result = subprocess.run([str(binary), "--stdio"],
                                input=b"".join((json.dumps(request) + "\n").encode()
                                               for request in requests),
                                cwd=cwd, env=env, capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, 10)):
        raise AssertionError("unexpected stdio response order")
    tools = {tool["name"]: tool["inputSchema"] for tool in responses[0]["result"]["tools"]}
    schema = tools["explain"]
    if (schema.get("additionalProperties") is not False
            or schema["properties"]["format"].get("enum") != ["json"]):
        raise AssertionError("explain schema advertises unsupported format")
    for response in responses[1:3]:
        content = response.get("result", {}).get("structuredContent", {})
        if response.get("error") or "explanation" not in content:
            raise AssertionError("valid omitted or explicit json format was rejected")
    for index in (3, 5, 7):
        error = responses[index].get("error", {})
        if (error.get("code"), error.get("message")) != (-400, "INVALID_REQUEST"):
            raise AssertionError("unsupported explain format was accepted")
        validation = responses[index + 1]["result"]["structuredContent"]
        if validation["valid"] is not False or not validation["errors"]:
            raise AssertionError("validate_payload accepted unsupported explain format")
    if b'"fomat"' in result.stdout + result.stderr:
        raise AssertionError("unknown field reflected in diagnostics")
    print("PASS packaged explain: only omitted/json format accepted; unknown arguments rejected")


if __name__ == "__main__":
    main()
