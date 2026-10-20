#!/usr/bin/env python3
"""Run the Redis recovery MCP probe inside pinned Alpine without host ports."""

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
    probe = Path(__file__).with_name("alpine_redis_recovery.py").resolve(strict=True)
    name = f"request-guard-alpine-redis-{os.getpid()}-{secrets.token_hex(4)}"
    command = [
        "docker", "run", "--rm", "--init", "--name", name,
        "--memory", "768m", "--cpus", "2", "--pids-limit", "128",
        "-v", f"{binary}:/test/request-guard-mcp:ro",
        "-v", f"{probe}:/test/alpine_redis_recovery.py:ro",
        ALPINE_IMAGE, "sh", "-ec",
        "apk add --no-cache python3 redis >/dev/null; "
        "python3 /test/alpine_redis_recovery.py /test/request-guard-mcp \"$1\"",
        "alpine-redis", args.expected_version,
    ]
    try:
        subprocess.run(command, check=True, timeout=240)
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


if __name__ == "__main__":
    main()
