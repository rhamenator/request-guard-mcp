#!/usr/bin/env python3
"""Verify the packaged self_test suite contract over stdio."""

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
    marker = "RG_SYNTHETIC_UNSUPPORTED_SUITE_9472"
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "self-test-suite-probe", "version": "1"},
        }},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    cases = ({}, {"suite": "all"}, {"suite": marker}, {"suite": ""},
             {"suite": None}, {"suite": 1})
    for request_id, arguments in enumerate(cases, 3):
        requests.append({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                         "params": {"name": "self_test", "arguments": arguments}})
    payload = b"".join((json.dumps(req, separators=(",", ":")) + "\n").encode()
                       for req in requests)
    with tempfile.TemporaryDirectory(prefix="rg-self-test-suite-") as cwd:
        result = subprocess.run(
            [str(binary), "--stdio"], input=payload,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", ""), "HOME": cwd}, cwd=cwd,
            timeout=20, check=False,
        )
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, 3 + len(cases))):
        raise AssertionError("unexpected stdio response count/order")
    if responses[0].get("result", {}).get("protocolVersion") != "2025-06-18":
        raise AssertionError("initialize failed")
    tool = next(tool for tool in responses[1]["result"]["tools"]
                if tool["name"] == "self_test")
    if tool["inputSchema"]["properties"]["suite"].get("enum") != ["all"]:
        raise AssertionError("self_test suite schema does not list the supported value")
    for response in responses[2:4]:
        content = response["result"]["structuredContent"]
        if content["failed"] != 0 or content["passed"] <= 0:
            raise AssertionError("supported self_test suite failed")
    for response in responses[4:]:
        if response.get("error", {}).get("code") != -400:
            raise AssertionError("unsupported suite returned a passing result")
    if marker.encode() in result.stdout + result.stderr:
        raise AssertionError("unsupported suite value was reflected into output")
    print("PASS packaged self_test: omitted/all run, unsupported suite rejected")


if __name__ == "__main__":
    main()
