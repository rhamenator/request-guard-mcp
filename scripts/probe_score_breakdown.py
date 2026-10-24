#!/usr/bin/env python3
"""Check a running binary's score_breakdown input contract over stdio."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def frame(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    marker = "RG_SYNTHETIC_INVALID_SCORE_FIELD_6821"
    cases = [
        {"signals": {marker: 1}},
        {"signals": [{"name": "ua_ai_bot", "value": 1, "weight": 1}]},
        {"signals": {"user_agent": 42}},
        {"signals": None},
        {"signal": {"user_agent": "GPTBot/1.0"}},
        {"signals": {"user_agent": "GPTBot/1.0", "path": "/"}},
        {},
    ]
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "score-breakdown-probe", "version": "1"},
        }},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    for index, arguments in enumerate(cases, 3):
        requests.append({"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": {
            "name": "score_breakdown", "arguments": arguments,
        }})
    with tempfile.TemporaryDirectory(prefix="rg-score-breakdown-") as cwd:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": cwd}
        result = subprocess.run(
            [str(binary), "--stdio"], input=b"".join(map(frame, requests)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd,
            timeout=20, check=False,
        )
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, 10)):
        raise AssertionError("unexpected stdio response count/order")
    tool = next(tool for tool in responses[1]["result"]["tools"]
                if tool["name"] == "score_breakdown")
    if "classification request metadata" not in tool["description"]:
        raise AssertionError("score_breakdown input shape is not advertised")
    if tool["inputSchema"]["properties"]["signals"].get("type") != "object":
        raise AssertionError("score_breakdown signals schema is not an object")
    for response in responses[2:7]:
        if response.get("error", {}).get("code") != -400:
            raise AssertionError("malformed supplied signals returned a clean score")
    valid = responses[7]["result"]["structuredContent"]
    if valid["total_score"] <= 0 or not valid["breakdown"]:
        raise AssertionError("valid metadata did not produce a rule breakdown")
    absent = responses[8]["result"]["structuredContent"]
    if absent["total_score"] != 0 or absent["breakdown"]:
        raise AssertionError("absent optional signals changed behavior")
    if marker.encode() in result.stdout + result.stderr:
        raise AssertionError("invalid field name was reflected into output")
    print("PASS packaged score_breakdown: malformed supplied signals rejected, valid metadata scored, absent field preserved")


if __name__ == "__main__":
    main()
