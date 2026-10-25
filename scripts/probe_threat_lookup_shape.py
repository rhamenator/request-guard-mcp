#!/usr/bin/env python3
"""Check packaged threat lookup request rejection without requiring Redis."""

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
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "threat-shape-probe", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "threat_lookup", "arguments": {"indicator": "AS64500", "typ": "asn"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "validate_payload", "arguments": {"tool": "threat_lookup",
                "payload": {"indicator": "AS64500", "typ": "asn"}}}},
    ]
    payload = b"".join((json.dumps(req, separators=(",", ":")) + "\n").encode()
                       for req in requests)
    with tempfile.TemporaryDirectory(prefix="rg-threat-shape-") as cwd:
        result = subprocess.run(
            [str(binary), "--stdio"], input=payload, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd,
            env={"PATH": os.environ.get("PATH", ""), "HOME": cwd},
            timeout=25, check=False)
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != [1, 2, 3, 4]:
        raise AssertionError("unexpected stdio response count/order")
    tools = {tool["name"]: tool for tool in responses[1]["result"]["tools"]}
    if tools["threat_lookup"]["inputSchema"].get("additionalProperties") is not False:
        raise AssertionError("schema accepts unknown arguments")
    if responses[2].get("error", {}).get("code") != -400:
        raise AssertionError("mistyped type was not rejected before backend lookup")
    if responses[3]["result"]["structuredContent"].get("valid") is not False:
        raise AssertionError("validate_payload accepted mistyped type")
    print("PASS packaged threat lookup: mistyped type rejected categorically")


if __name__ == "__main__":
    main()
