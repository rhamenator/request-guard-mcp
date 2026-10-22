#!/usr/bin/env python3
"""Ensure a build without Redis TLS fails closed for a rediss:// URL."""

import os
from pathlib import Path
import subprocess
import sys


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    env = os.environ.copy()
    env.update({
        "AUTH_TOKENS": "synthetic-redis-tls-probe-token-1234567890",
        "MCP__HOST": "127.0.0.1",
        "MCP__PORT": "0",
        "MCP__REDIS__URL": "rediss://127.0.0.1:1",
    })
    result = subprocess.run(
        [str(binary)], env=env, capture_output=True, text=True, timeout=5,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, "unsupported Redis TLS started a listener"
    assert "can't connect with TLS, the feature is not enabled" in output, output
    assert env["AUTH_TOKENS"] not in output, "synthetic token leaked to logs"
    print("unsupported rediss:// rejected before listener startup")


if __name__ == "__main__":
    main()
