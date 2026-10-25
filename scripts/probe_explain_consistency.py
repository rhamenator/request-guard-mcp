#!/usr/bin/env python3
"""Check that packaged explain cannot turn a blocked response into a clean result."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    classification = {"request_id": "synthetic-explain-probe", "path": "/admin", "method": "GET"}
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}}
    with tempfile.TemporaryDirectory(prefix="rg-explain-") as cwd:
        env["HOME"] = cwd

        def call(name: str, args: dict) -> dict:
            message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": args}}
            result = subprocess.run([str(binary), "--stdio"], cwd=cwd, env=env,
                                    input=(json.dumps(message) + "\n").encode(),
                                    capture_output=True, timeout=20, check=False)
            if result.returncode != 0 or len(result.stdout.splitlines()) != 1:
                raise AssertionError("stdio call failed")
            return json.loads(result.stdout)

        classified = call("classify", classification)["result"]["structuredContent"]
        if classified["verdict"] != "block":
            raise AssertionError("sensitive request did not block")
        supplied = call("explain", {"classification": classified})["result"]["structuredContent"]
        if ("verdict 'block'" not in supplied["explanation"]
                or "Caller-supplied classification" not in supplied["explanation"]
                or "path_sensitive" not in {x["name"] for x in supplied["factors"]}):
            raise AssertionError("supplied blocked response was explained as clean")
        recomputed = call("explain", {"classification": classification})["result"]["structuredContent"]
        if "verdict 'block'" not in recomputed["explanation"]:
            raise AssertionError("raw request was explained as clean")
        for malformed in ({"verdict": "block", "score": 0.9}, {"pah": "/admin"}):
            result = call("explain", {"classification": malformed})
            if result.get("error", {}).get("message") != "INVALID_REQUEST":
                raise AssertionError("malformed classification was accepted")
    print("PASS packaged explain: supplied response and raw request stay blocked; malformed input rejected")


if __name__ == "__main__":
    main()
