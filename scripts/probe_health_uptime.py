#!/usr/bin/env python3
"""Check that first-call health uptime includes time before the health call."""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def frame(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def main():
    binary = Path(sys.argv[1]).resolve(strict=True)
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}}
    env["MCP__AUTH__ENABLED"] = "true"
    env["AUTH_TOKENS"] = "SYNTHETIC_HEALTH_UPTIME_PROBE_12345678"

    with tempfile.TemporaryDirectory(prefix="request-guard-health-uptime-") as cwd:
        env["HOME"] = cwd
        process = subprocess.Popen([str(binary), "--stdio"], cwd=cwd, env=env,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        try:
            time.sleep(3)
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "uptime-probe", "version": "1"}}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                    "name": "health", "arguments": {}}},
            ]
            stdout, stderr = process.communicate(b"".join(map(frame, requests)), timeout=15)
        except BaseException:
            process.kill()
            process.communicate()
            raise

    if process.returncode != 0:
        raise RuntimeError(f"server exited {process.returncode}: {stderr[-300:]!r}")
    responses = [json.loads(line) for line in stdout.splitlines()]
    health = next((response for response in responses if response.get("id") == 2), None)
    if health is None or "error" in health or health.get("result", {}).get("isError"):
        raise RuntimeError("health tool did not return a normal result")
    uptime = health["result"]["structuredContent"]["uptime_seconds"]
    if uptime < 2:
        raise RuntimeError(f"first health call omitted elapsed pre-call uptime: {uptime}")
    print(f"PASS first-call health uptime includes pre-call elapsed time ({uptime}s)")


if __name__ == "__main__":
    main()
