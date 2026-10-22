#!/usr/bin/env python3
"""Ensure rediss:// fails closed until Redis TLS and the docs are qualified."""

import os
from pathlib import Path
import subprocess
import sys


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("MCP__") and key not in {"AUTH_TOKENS", "CONFIG_FILE"}}
    env.update({
        "AUTH_TOKENS": "synthetic-redis-tls-probe-token-1234567890",
        "MCP__AUTH__ENABLED": "true",
        "MCP__HOST": "127.0.0.1",
        "MCP__PORT": "0",
        "MCP__REDIS__URL": "rediss://127.0.0.1:1",
    })
    try:
        result = subprocess.run(
            [str(binary)], env=env, capture_output=True, text=True, timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise AssertionError("rediss:// startup did not fail within 5 seconds") from error
    output = result.stdout + result.stderr
    assert result.returncode != 0, "unsupported Redis TLS started a listener"
    assert "failed to create configured Redis pool" in output, output
    assert "TLS" in output and "feature is not enabled" in output, output
    assert env["AUTH_TOKENS"] not in output, "synthetic token leaked to logs"
    print("unsupported rediss:// rejected before listener startup")


if __name__ == "__main__":
    main()
