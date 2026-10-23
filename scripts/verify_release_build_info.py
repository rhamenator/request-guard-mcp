#!/usr/bin/env python3
"""Check the build metadata reported by an extracted native release binary."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


def frame(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-rust-version", required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
        raise ValueError("expected commit must be a full lowercase Git SHA")
    binary = args.binary.resolve(strict=True)
    requests = b"".join(
        (
            frame({
                "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "release-build-info-check", "version": "1"},
                },
            }),
            frame({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            frame({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "model_info", "arguments": {}},
            }),
        )
    )
    essentials = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}
    env = {key: value for key, value in os.environ.items() if key.upper() in essentials}
    env["MCP__AUTH__ENABLED"] = "false"
    with tempfile.TemporaryDirectory(prefix="request-guard-build-info-") as cwd:
        env["HOME"] = cwd
        result = subprocess.run(
            [str(binary), "--stdio"], input=requests, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd, env=env, timeout=30, check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(f"stdio child exited {result.returncode}: {result.stderr[-500:]!r}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != [1, 2]:
        raise RuntimeError("unexpected protocol response order or stdout contamination")
    build = responses[1]["result"]["structuredContent"]["build_info"]
    expected = {
        "version": args.expected_version,
        "git_commit": args.expected_commit,
        "rust_version": args.expected_rust_version,
    }
    for key, value in expected.items():
        if build.get(key) != value:
            raise RuntimeError(f"packaged {key} does not match expected release input")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", build.get("build_date", "")):
        raise RuntimeError("packaged UTC build date is missing or malformed")
    print("PASS packaged build_info: version, source commit, Rust toolchain, UTC build date")


if __name__ == "__main__":
    main()
