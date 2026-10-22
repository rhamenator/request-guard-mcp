#!/usr/bin/env python3
"""Run PostgreSQL recovery MCP probe inside pinned Alpine without host ports."""

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
    probe = Path(__file__).with_name("alpine_postgres_recovery.py").resolve(strict=True)
    migration = Path(__file__).with_name("postgres_minimize_legacy.sql").resolve(strict=True)
    install = Path(__file__).resolve().parent.parent / "INSTALL.md"
    retention_sql = "DELETE FROM mcp_decisions WHERE created_at < NOW() - INTERVAL '30 days';"
    if retention_sql not in install.read_text(encoding="utf-8"):
        raise RuntimeError("packaged PostgreSQL probe no longer matches the INSTALL retention SQL")
    name = f"request-guard-alpine-pg-{os.getpid()}-{secrets.token_hex(4)}"
    command = [
        "docker", "run", "--rm", "--init", "--name", name,
        "--memory", "1g", "--cpus", "2", "--pids-limit", "128",
        "--tmpfs", "/tmp:rw,size=256m",
        "-v", f"{binary}:/test/request-guard-mcp:ro",
        "-v", f"{probe}:/test/alpine_postgres_recovery.py:ro",
        "-v", f"{migration}:/test/postgres_minimize_legacy.sql:ro",
        ALPINE_IMAGE, "sh", "-ec",
        "apk add --no-cache python3 postgresql18 >/dev/null; "
        "python3 /test/alpine_postgres_recovery.py /test/request-guard-mcp \"$1\"",
        "alpine-postgres", args.expected_version,
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
                raise RuntimeError("disposable PostgreSQL test container did not stop") from None


if __name__ == "__main__":
    main()
