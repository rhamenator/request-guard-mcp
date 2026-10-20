#!/usr/bin/env python3
"""Run the pinned official MCP Inspector in Alpine on an extracted musl binary."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import subprocess

from smoke_alpine_musl import ALPINE_IMAGE


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    inspector_script = Path(__file__).with_name("inspector_smoke.py").resolve(strict=True)
    name = f"request-guard-inspector-alpine-{os.getpid()}-{secrets.token_hex(4)}"
    command = [
        "docker", "run", "--rm", "--init", "--name", name, "--network", "bridge",
        "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
        "--mount", f"type=bind,src={binary},dst=/test/request-guard-mcp,readonly",
        "--mount", f"type=bind,src={inspector_script},dst=/test/inspector_smoke.py,readonly",
        ALPINE_IMAGE, "sh", "-ec",
        "apk add --no-cache python3 nodejs npm >/dev/null; "
        "python3 /test/inspector_smoke.py --expected-version \"$1\" "
        "/test/request-guard-mcp > /tmp/inspector.log 2>&1 || "
        "{ echo 'Alpine Inspector failed; test output withheld to protect its bearer token' >&2; exit 1; }; "
        "grep '^PASS ' /tmp/inspector.log",
        "inspector-alpine", args.expected_version,
    ]
    try:
        subprocess.run(command, check=True, timeout=360)
    finally:
        # A timeout kills the Docker CLI, not necessarily its container.
        subprocess.run(["docker", "rm", "-f", name], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    print("PASS official MCP Inspector executed inside pinned Alpine image")


if __name__ == "__main__":
    main()
