#!/usr/bin/env python3
"""Verify canary context spelling against a running stdio binary."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    marker = "RG_SYNTHETIC_CANARY_TYPO_6942"
    valid = {"token": "synthetic-canary-not-registered", "context": {"path": "/probe"}}
    typo = {"token": "synthetic-canary-not-registered", "contex": {"path": marker}}
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "canary-shape-probe", "version": "1"},
        }},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "validate_payload", "arguments": {"tool": "canary_eval", "payload": valid},
        }},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "validate_payload", "arguments": {"tool": "canary_eval", "payload": typo},
        }},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": "canary_eval", "arguments": typo,
        }},
    ]
    payload = b"".join((json.dumps(req, separators=(",", ":")) + "\n").encode()
                       for req in requests)
    with tempfile.TemporaryDirectory(prefix="rg-canary-shape-") as cwd:
        result = subprocess.run(
            [str(binary), "--stdio"], input=payload,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", ""), "HOME": cwd}, cwd=cwd,
            timeout=20, check=False,
        )
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != [1, 2, 3, 4, 5]:
        raise AssertionError("unexpected stdio response count/order")
    if responses[0].get("result", {}).get("protocolVersion") != "2025-06-18":
        raise AssertionError("initialize failed")
    tool = next(tool for tool in responses[1]["result"]["tools"]
                if tool["name"] == "canary_eval")
    if tool["inputSchema"].get("additionalProperties") is not False:
        raise AssertionError("canary_eval schema permits unknown arguments")
    if responses[2]["result"]["structuredContent"].get("valid") is not True:
        raise AssertionError("valid canary context was rejected")
    if responses[3]["result"]["structuredContent"].get("valid") is not False:
        raise AssertionError("misspelled canary context passed validation")
    if responses[4].get("error", {}).get("code") != -400:
        raise AssertionError("misspelled canary context reached the callable tool")
    if marker.encode() in result.stdout + result.stderr:
        raise AssertionError("misspelled value was reflected into output")
    print("PASS packaged canary_eval: context accepted, typo rejected")


if __name__ == "__main__":
    main()
