#!/usr/bin/env python3
"""Reject unknown drift, calibration and queue fields in packaged stdio calls."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    bad = [
        ("drift_report", {"window_hors": 48}),
        ("calibration_report", {"window_hors": 48}),
        ("queue_status", {"queu": "target"}),
    ]
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}]
    for name, payload in bad:
        requests.append({"jsonrpc": "2.0", "id": len(requests) + 1,
                         "method": "tools/call", "params": {"name": name, "arguments": payload}})
        requests.append({"jsonrpc": "2.0", "id": len(requests) + 1,
                         "method": "tools/call", "params": {"name": "validate_payload",
                                                              "arguments": {"tool": name, "payload": payload}}})
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}}
    with tempfile.TemporaryDirectory(prefix="rg-report-input-") as cwd:
        env["HOME"] = cwd
        result = subprocess.run([str(binary), "--stdio"],
                                input=b"".join((json.dumps(request) + "\n").encode()
                                               for request in requests),
                                cwd=cwd, env=env, capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, 8)):
        raise AssertionError("unexpected stdio response order")
    tools = {tool["name"]: tool["inputSchema"] for tool in responses[0]["result"]["tools"]}
    if any(tools[name].get("additionalProperties") is not False for name, _ in bad):
        raise AssertionError("reporting input schema is not strict")
    for index in (1, 3, 5):
        error = responses[index].get("error", {})
        if (error.get("code"), error.get("message")) != (-400, "INVALID_REQUEST"):
            raise AssertionError("callable reporting tool accepted a misspelled field")
        validation = responses[index + 1]["result"]["structuredContent"]
        if validation["valid"] is not False or not validation["errors"]:
            raise AssertionError("validate_payload accepted a misspelled reporting field")
    if b"window_hors" in result.stdout + result.stderr or b'"queu"' in result.stdout + result.stderr:
        raise AssertionError("misspelled field reflected in output")
    print("PASS packaged reporting: drift, calibration and queue unknown fields rejected")


if __name__ == "__main__":
    main()
