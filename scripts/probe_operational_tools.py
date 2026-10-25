#!/usr/bin/env python3
"""Check operational tool argument shapes and categorical name errors over stdio."""

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
    marker = "RG_SYNTHETIC_UNKNOWN_OPS_NAME_7194"
    cases = [
        ("feature_flags", {}),
        ("feature_flags", {"flag": "batch_classify"}),
        ("feature_flags", {"flags": "batch_classify"}),
        ("feature_flags", {"flag": marker}),
        ("warmup", {"target": "cache"}),
        ("warmup", {"targt": "cache"}),
        ("warmup", {"target": marker}),
        ("config_snapshot", {"redact_secrets": True}),
        ("config_snapshot", {"redact_secret": False}),
        ("feature_flags", {"flag": None}),
        ("warmup", {"target": None}),
        ("config_snapshot", {"redact_secrets": None}),
    ]
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "operational-tools-probe", "version": "1"},
        }},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    requests.extend({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                     "params": {"name": name, "arguments": arguments}}
                    for i, (name, arguments) in enumerate(cases, 3))
    for i, (tool, payload) in enumerate((
            ("feature_flags", {"flags": "batch_classify"}),
            ("warmup", {"targt": "cache"}),
            ("config_snapshot", {"redact_secret": False}),
            ("feature_flags", {"flag": marker}),
            ("warmup", {"target": marker}),
    ), start=15):
        requests.append({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                         "params": {"name": "validate_payload",
                                    "arguments": {"tool": tool, "payload": payload}}})
    payload = b"".join((json.dumps(req, separators=(",", ":")) + "\n").encode()
                       for req in requests)
    with tempfile.TemporaryDirectory(prefix="rg-ops-tools-") as cwd:
        result = subprocess.run(
            [str(binary), "--stdio"], input=payload,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", ""), "HOME": cwd}, cwd=cwd,
            timeout=25, check=False,
        )
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, 20)):
        raise AssertionError("unexpected stdio response count/order")
    if responses[0].get("result", {}).get("protocolVersion") != "2025-06-18":
        raise AssertionError("initialize failed")
    tools = {tool["name"]: tool for tool in responses[1]["result"]["tools"]}
    if tools["warmup"]["inputSchema"]["properties"]["target"].get("enum") != [
            "all", "rule_engine", "scorer", "cache"]:
        raise AssertionError("warmup schema omits supported target enum")
    for name in ("feature_flags", "warmup", "config_snapshot"):
        if tools[name]["inputSchema"].get("additionalProperties") is not False:
            raise AssertionError(f"{name} schema accepts unknown arguments")
    if "batch_classify" not in responses[2]["result"]["structuredContent"]["flags"]:
        raise AssertionError("feature flag listing failed")
    if list(responses[3]["result"]["structuredContent"]["flags"]) != ["batch_classify"]:
        raise AssertionError("supported named feature flag lookup failed")
    if "cache" not in responses[6]["result"]["structuredContent"]["warmed"]:
        raise AssertionError("supported warmup target failed")
    if "snapshot" not in responses[9]["result"]["structuredContent"]:
        raise AssertionError("redacted config snapshot failed")
    for i in (4, 5, 7, 8, 10, 11, 12, 13):
        if responses[i].get("error", {}).get("code") != -400:
            raise AssertionError(f"invalid operational argument returned success: id {i + 1}")
    for response in responses[14:]:
        if response["result"]["structuredContent"].get("valid") is not False:
            raise AssertionError("structural validator accepted a misspelled argument")
    if marker.encode() in result.stdout + result.stderr:
        raise AssertionError("unsupported name was reflected in output")
    print("PASS packaged operational tools: valid calls and categorical typo/name errors")


if __name__ == "__main__":
    main()
