#!/usr/bin/env python3
"""Exercise an extracted release binary's stdio transport without SDK dependencies."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def message(request):
    return json.dumps(request, separators=(",", ":")).encode() + b"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)

    observed = {"ip": "192.0.2.1", "user_agent": "GPTBot/1.0", "path": "/"}
    frames = [
        message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "stdio-release-smoke", "version": "1"},
        }}),
        message({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        message({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "classify", "arguments": observed,
        }}),
        message({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "explain", "arguments": {"classification": observed},
        }}),
        b"x" * 1025 + b"\n",
        b"\xff\n",
        message({"jsonrpc": "2.0", "id": 5, "method": "ping"}),
    ]
    essentials = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}
    env = {key: value for key, value in os.environ.items() if key.upper() in essentials}
    env["MCP__LIMITS__MAX_REQUEST_BYTES"] = "1024"
    with tempfile.TemporaryDirectory(prefix="request-guard-stdio-release-") as cwd:
        env["HOME"] = cwd
        result = subprocess.run([str(binary), "--stdio"], input=b"".join(frames),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=cwd, env=env, timeout=30, check=False)
    require(result.returncode == 0, f"stdio child exited {result.returncode}: {result.stderr[-500:]!r}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    require([response["id"] for response in responses] == [1, 2, 3, 4, None, None, 5],
            "unexpected response count/order or stdout contamination")
    require(responses[0]["result"]["protocolVersion"] == "2025-06-18", "wrong protocol version")
    require(responses[0]["result"]["serverInfo"]["version"] == args.expected_version,
            "wrong server version")
    require({"classify", "explain"} <= {tool["name"] for tool in responses[1]["result"]["tools"]},
            "core tools missing")
    require(responses[2]["result"]["structuredContent"]["verdict"] == "block", "classify failed")
    require(bool(responses[3]["result"]["structuredContent"]["factors"]), "explain failed")
    require(responses[4]["error"]["code"] == -413, "oversized line was not rejected")
    require(responses[5]["error"]["code"] == -32700, "malformed UTF-8 was not rejected")
    require(responses[6]["result"] == {}, "server did not recover after malformed lines")
    print("PASS packaged stdio: initialize, tools, one-way notification, bounded errors, recovery")


if __name__ == "__main__":
    main()
