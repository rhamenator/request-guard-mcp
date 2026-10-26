#!/usr/bin/env python3
"""Check encoded traversal diagnostics in a packaged stdio binary."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    cases = [
        ("%2E%2E%2Fetc/passwd", "traversal", True),
        ("..%2fetc/passwd", "traversal", True),
        ("..%5Cwindows", "traversal", True),
        ("%2E%2E%2Fetc/passwd", "ai_attack", False),
        ("ordinary/docs/path", "traversal", False),
    ]
    requests = [
        {
            "jsonrpc": "2.0",
            "id": index,
            "method": "tools/call",
            "params": {
                "name": "abuse_pattern_match",
                "arguments": {"text": text, "categories": [category]},
            },
        }
        for index, (text, category, _) in enumerate(cases, start=1)
    ]
    env = {
        key: value for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}
    }
    with tempfile.TemporaryDirectory(prefix="rg-abuse-encoded-") as cwd:
        env["HOME"] = cwd
        result = subprocess.run(
            [str(binary), "--stdio"],
            input=b"".join((json.dumps(request) + "\n").encode() for request in requests),
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=20,
            check=False,
        )
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, len(cases) + 1)):
        raise AssertionError("unexpected stdio response order")
    for (text, category, expected), response in zip(cases, responses):
        content = response["result"]["structuredContent"]
        if content["matched"] is not expected:
            raise AssertionError(f"unexpected result for {text!r} in {category}")
        if expected and not any(
            pattern["pattern"] == "path_traversal" for pattern in content["patterns"]
        ):
            raise AssertionError(f"traversal pattern absent for {text!r}")
    print("PASS packaged abuse traversal: encoded case and separators")


if __name__ == "__main__":
    main()
