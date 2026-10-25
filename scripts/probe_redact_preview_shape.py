#!/usr/bin/env python3
"""Check packaged redact_preview custom fields and misspelling rejection."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    marker = "RG_SYNTHETIC_REDACT_FIELD_6942"
    valid = {"payload": {"access_token": marker}, "fields": ["access_token"]}
    typo = {"payload": {"access_token": marker}, "field": ["access_token"]}
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "redact-shape-probe", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "redact_preview", "arguments": valid}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "validate_payload", "arguments": {
                "tool": "redact_preview", "payload": typo}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": "redact_preview", "arguments": typo}},
    ]
    payload = b"".join((json.dumps(req, separators=(",", ":")) + "\n").encode()
                       for req in requests)
    with tempfile.TemporaryDirectory(prefix="rg-redact-shape-") as cwd:
        result = subprocess.run(
            [str(binary), "--stdio"], input=payload, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd,
            env={"PATH": os.environ.get("PATH", ""), "HOME": cwd},
            timeout=20, check=False)
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != [1, 2, 3, 4, 5]:
        raise AssertionError("unexpected stdio response count/order")
    tools = {tool["name"]: tool for tool in responses[1]["result"]["tools"]}
    if tools["redact_preview"]["inputSchema"].get("additionalProperties") is not False:
        raise AssertionError("redact_preview schema permits unknown arguments")
    redacted = responses[2]["result"]["structuredContent"]
    if redacted.get("redacted", {}).get("access_token") != "[REDACTED]":
        raise AssertionError("explicit custom field was not redacted")
    if redacted.get("fields_redacted") != ["access_token"]:
        raise AssertionError("custom field was not reported")
    if responses[3]["result"]["structuredContent"].get("valid") is not False:
        raise AssertionError("validate_payload accepted misspelled fields")
    if responses[4].get("error", {}).get("code") != -400:
        raise AssertionError("callable redact_preview accepted misspelled fields")
    if marker.encode() in result.stdout + result.stderr:
        raise AssertionError("secret marker was reflected in output")
    print("PASS packaged redact_preview: custom key redacted, typo rejected")


if __name__ == "__main__":
    main()
