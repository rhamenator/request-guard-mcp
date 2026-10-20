#!/usr/bin/env python3
"""Run packaged PostgreSQL TLS trust probes inside pinned Alpine."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys

from smoke_alpine_musl import ALPINE_IMAGE


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    probe = Path(__file__).with_name("alpine_postgres_tls.py").resolve(strict=True)
    recovery = Path(__file__).with_name("alpine_postgres_recovery.py").resolve(strict=True)
    name = f"request-guard-alpine-pg-tls-{os.getpid()}-{secrets.token_hex(4)}"
    command = [
        "docker", "run", "--rm", "--init", "--name", name,
        "--memory", "1g", "--cpus", "2", "--pids-limit", "128",
        "--tmpfs", "/tmp:rw,size=256m",
        "--add-host", "pgci.test:127.0.0.1",
        "-v", f"{binary}:/test/request-guard-mcp:ro",
        "-v", f"{probe}:/test/alpine_postgres_tls.py:ro",
        "-v", f"{recovery}:/test/alpine_postgres_recovery.py:ro",
        ALPINE_IMAGE, "sh", "-ec",
        "apk add --no-cache ca-certificates openssl python3 postgresql18 >/dev/null; "
        "python3 /test/alpine_postgres_tls.py /test/request-guard-mcp \"$1\"",
        "alpine-postgres-tls", args.expected_version,
    ]
    try:
        subprocess.run(command, check=True, timeout=300)
    finally:
        pending_failure = sys.exc_info()[0] is not None
        try:
            subprocess.run(["docker", "rm", "-f", name], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        except subprocess.TimeoutExpired:
            if not pending_failure:
                raise RuntimeError("disposable PostgreSQL TLS test container did not stop") from None


if __name__ == "__main__":
    main()
