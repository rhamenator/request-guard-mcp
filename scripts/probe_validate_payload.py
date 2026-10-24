#!/usr/bin/env python3
"""Check packaged MCP validate_payload against representative callable request shapes."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def frame(request):
    return json.dumps(request, separators=(",", ":")).encode() + b"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    marker = "RG_SYNTHETIC_VALIDATION_MARKER_6821"
    cases = [
        ("classify", {}, True),
        ("batch_classify", {"items": []}, True),
        ("feedback", {"request_id": "synthetic", "correct_verdict": "allow"}, True),
        ("feedback", {"request_id": marker, "correct_verdict": False}, False),
        ("explain", {}, False),
        ("enrich_ip", {"ip": 7}, False),
        ("unknown_tool_" + marker, {}, False),
    ]
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "validate-payload-probe", "version": "1"},
        }},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    for index, (name, payload, _) in enumerate(cases, 2):
        requests.append({"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": {
            "name": "validate_payload", "arguments": {"tool": name, "payload": payload},
        }})
    requests.append({"jsonrpc": "2.0", "id": len(cases) + 2,
                     "method": "tools/call", "params": {
                         "name": "classify", "arguments": {},
                     }})
    requests.append({"jsonrpc": "2.0", "id": len(cases) + 3,
                     "method": "tools/call", "params": {
                         "name": "explain", "arguments": {},
                     }})
    with tempfile.TemporaryDirectory(prefix="rg-validate-payload-") as cwd:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": cwd}
        result = subprocess.run(
            [str(binary), "--stdio"], input=b"".join(map(frame, requests)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env,
            timeout=20, check=False,
        )
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, len(cases) + 4)):
        raise AssertionError("unexpected stdio responses")
    for response, (name, _, expected) in zip(responses[1:], cases):
        actual = response["result"]["structuredContent"]
        if actual["valid"] is not expected or bool(actual["errors"]) is expected:
            raise AssertionError(f"incorrect structural result for {name}")
        if marker in json.dumps(actual):
            raise AssertionError("invalid input value reflected in validation result")
    if marker.encode() in result.stderr:
        raise AssertionError("invalid input marker appeared in diagnostics")
    if responses[-2]["result"]["structuredContent"]["verdict"] not in {
        "allow", "block", "challenge", "flag", "unknown",
    }:
        raise AssertionError("empty classify was rejected by callable tool")
    if responses[-1].get("error", {}).get("code") != -400:
        raise AssertionError("missing explain classification was accepted by callable tool")
    print("PASS packaged validate_payload: valid, invalid, unknown and callable agreement")


if __name__ == "__main__":
    main()
