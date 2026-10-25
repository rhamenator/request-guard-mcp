#!/usr/bin/env python3
"""Reject misspelled classify metadata in callable, batch and validation paths."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    marker = "RG_SYNTHETIC_CLASSIFY_FIELD_317"
    typo = {"pah_" + marker: "/admin"}
    calls = [
        ("classify", {"path": "/admin"}),
        ("classify", typo),
        ("validate_payload", {"tool": "classify", "payload": typo}),
        ("batch_classify", {"items": [typo]}),
        ("batch_classify", {"items": [], "option": {"fail_fast": True}}),
        ("classify", {"tls_fingerprint_verified": True}),
        ("classify", {"extra": {"custom_field": "synthetic"}}),
        ("classify", {}),
    ]
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    ]
    requests.extend(
        {"jsonrpc": "2.0", "id": index, "method": "tools/call",
         "params": {"name": name, "arguments": arguments}}
        for index, (name, arguments) in enumerate(calls, 2)
    )
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}}
    with tempfile.TemporaryDirectory(prefix="rg-classify-fields-") as cwd:
        env["HOME"] = cwd
        result = subprocess.run(
            [str(binary), "--stdio"],
            input=b"".join((json.dumps(request) + "\n").encode() for request in requests),
            cwd=cwd, env=env, capture_output=True, timeout=20, check=False,
        )
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, 10)):
        raise AssertionError("unexpected stdio response order")
    tools = {tool["name"]: tool["inputSchema"]
             for tool in responses[0]["result"]["tools"]}
    classify = tools["classify"]
    batch = tools["batch_classify"]
    if (classify.get("additionalProperties") is not False
            or batch.get("additionalProperties") is not False
            or batch["properties"]["items"]["items"] != classify
            or "tls_fingerprint_verified" in classify["properties"]):
        raise AssertionError("classify or batch item schema is not strict")
    if responses[1]["result"]["structuredContent"]["verdict"] != "block":
        raise AssertionError("valid sensitive path was not blocked")
    for response in (responses[2], responses[4], responses[5], responses[6]):
        error = response.get("error", {})
        if (error.get("code"), error.get("message")) != (-400, "INVALID_REQUEST"):
            raise AssertionError("unknown or server-derived field was accepted")
    validation = responses[3]["result"]["structuredContent"]
    if validation["valid"] is not False or not validation["errors"]:
        raise AssertionError("validate_payload accepted misspelled classify field")
    for response in responses[7:]:
        if response.get("error") or "verdict" not in response["result"]["structuredContent"]:
            raise AssertionError("valid custom extra or empty classify request was rejected")
    if marker.encode() in result.stdout + result.stderr:
        raise AssertionError("unknown field name reflected into diagnostics")
    print("PASS packaged classify: unknown metadata and batch fields rejected; valid partial inputs preserved")


if __name__ == "__main__":
    main()
