#!/usr/bin/env python3
"""Run a packaged musl server against trusted and untrusted Alpine TLS collectors."""

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
    probe = Path(__file__).with_name("alpine_otlp_tls.py").resolve(strict=True)
    name = f"request-guard-alpine-otlp-{os.getpid()}-{secrets.token_hex(4)}"
    command = [
        "docker", "run", "--rm", "--init", "--name", name,
        "--memory", "1g", "--cpus", "2", "--pids-limit", "128",
        "--tmpfs", "/tmp:rw,size=64m",
        "-v", f"{binary}:/test/request-guard-mcp:ro",
        "-v", f"{probe}:/test/alpine_otlp_tls.py:ro",
        ALPINE_IMAGE, "sh", "-ec",
        "apk add --no-cache python3 py3-grpcio openssl ca-certificates >/dev/null; "
        "python3 /test/alpine_otlp_tls.py /test/request-guard-mcp \"$1\"",
        "alpine-otlp", args.expected_version,
    ]
    try:
        subprocess.run(command, check=True, timeout=300)
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


if __name__ == "__main__":
    main()
