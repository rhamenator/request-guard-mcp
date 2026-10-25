#!/usr/bin/env python3
"""Check remaining advertised strict tool inputs in a packaged stdio binary."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    cases = [
        ("replay_decision", {"request_id": "synthetic-id", "deterministic": True}, "determinitsic"),
        ("enrich_ip", {"ip": "127.0.0.1"}, "ipp"),
        ("enrich_asn", {"asn": 64512}, "asnn"),
        ("enrich_ua", {"user_agent": "Mozilla/5.0"}, "user_agnet"),
        ("validate_payload", {"tool": "self_test", "payload": {}}, "toool"),
        ("self_test", {"suite": "all"}, "sutie"),
    ]
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}]
    for name, good, typo in cases:
        bad = dict(good, **{typo: "synthetic"})
        for payload, valid in ((good, True), (bad, False)):
            requests.append({"jsonrpc": "2.0", "id": len(requests) + 1,
                             "method": "tools/call", "params": {
                                 "name": "validate_payload", "arguments": {
                                     "tool": name, "payload": payload}}})
        requests.append({"jsonrpc": "2.0", "id": len(requests) + 1,
                         "method": "tools/call", "params": {"name": name, "arguments": bad}})
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}}
    with tempfile.TemporaryDirectory(prefix="rg-remaining-input-") as cwd:
        env["HOME"] = cwd
        result = subprocess.run([str(binary), "--stdio"],
                                input=b"".join((json.dumps(request) + "\n").encode()
                                               for request in requests), cwd=cwd, env=env,
                                capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, len(requests) + 1)):
        raise AssertionError("unexpected stdio response order")
    tools = {tool["name"]: tool["inputSchema"] for tool in responses[0]["result"]["tools"]}
    offset = 1
    for name, _, _ in cases:
        if tools[name].get("additionalProperties") is not False:
            raise AssertionError(f"{name} schema is not strict")
        for valid in (True, False):
            observed = responses[offset]["result"]["structuredContent"]["valid"]
            if observed is not valid:
                raise AssertionError(f"{name} validator returned {observed}, expected {valid}")
            offset += 1
        error = responses[offset].get("error", {})
        if (error.get("code"), error.get("message")) != (-400, "INVALID_REQUEST"):
            raise AssertionError(f"{name} callable accepted unknown field")
        offset += 1
    print("PASS packaged remaining tool inputs reject unknown fields")


if __name__ == "__main__":
    main()
