#!/usr/bin/env python3
"""Check packaged feedback and abuse argument shapes through stdio."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    cases = [
        ("abuse_pattern_match", {"text": "SELECT a FROM t", "categories": ["injection"]},
         {"text": "SELECT a FROM t", "categorie": ["injection"]}),
        ("feedback", {"request_id": "synthetic-id", "correct_verdict": "allow",
                      "notes": "synthetic-note", "reporter": "synthetic-reporter"},
         {"request_id": "synthetic-id", "correct_verdict": "allow",
          "notse": "synthetic-note"}),
    ]
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}]
    for name, good, bad in cases:
        for payload in (good, bad):
            requests.append({"jsonrpc": "2.0", "id": len(requests) + 1,
                             "method": "tools/call", "params": {"name": name, "arguments": payload}})
            requests.append({"jsonrpc": "2.0", "id": len(requests) + 1,
                             "method": "tools/call", "params": {"name": "validate_payload",
                                                                  "arguments": {"tool": name,
                                                                                "payload": payload}}})
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}}
    with tempfile.TemporaryDirectory(prefix="rg-secondary-input-") as cwd:
        env["HOME"] = cwd
        result = subprocess.run([str(binary), "--stdio"],
                                input=b"".join((json.dumps(request) + "\n").encode()
                                               for request in requests),
                                cwd=cwd, env=env, capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, 10)):
        raise AssertionError("unexpected stdio response order")
    tools = {tool["name"]: tool["inputSchema"] for tool in responses[0]["result"]["tools"]}
    if any(tools[name].get("additionalProperties") is not False for name, _, _ in cases):
        raise AssertionError("secondary input schema is not strict")
    if not responses[1]["result"]["structuredContent"]["matched"]:
        raise AssertionError("valid abuse filter no longer matches")
    if responses[2]["result"]["structuredContent"]["valid"] is not True:
        raise AssertionError("valid abuse filter rejected by validator")
    if (responses[3].get("error", {}).get("code"),
            responses[3].get("error", {}).get("message")) != (-400, "INVALID_REQUEST"):
        raise AssertionError("abuse tool accepted misspelled categories")
    if responses[4]["result"]["structuredContent"]["valid"] is not False:
        raise AssertionError("validator accepted misspelled categories")
    # PostgreSQL is intentionally unconfigured; a valid feedback call reaches
    # the backend boundary, while a malformed one must fail during decoding.
    if responses[5].get("error", {}).get("message") != "INTEGRATION_UNAVAILABLE":
        raise AssertionError("valid feedback did not reach backend boundary")
    if responses[6]["result"]["structuredContent"]["valid"] is not True:
        raise AssertionError("valid feedback rejected by validator")
    if (responses[7].get("error", {}).get("code"),
            responses[7].get("error", {}).get("message")) != (-400, "INVALID_REQUEST"):
        raise AssertionError("feedback tool accepted misspelled notes")
    if responses[8]["result"]["structuredContent"]["valid"] is not False:
        raise AssertionError("validator accepted misspelled notes")
    if b"categorie" in result.stdout + result.stderr or b"notse" in result.stdout + result.stderr:
        raise AssertionError("misspelled field reflected in output")
    print("PASS packaged secondary inputs: feedback and abuse unknown fields rejected")


if __name__ == "__main__":
    main()
