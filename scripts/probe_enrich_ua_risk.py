#!/usr/bin/env python3
"""Check packaged user-agent enrichment score against named scanner patterns."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    agents = [
        "sqlmap/1.7", "Nikto/2.1.6", "masscan/1.3",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "ua-risk-probe", "version": "1"}}}]
    requests.append({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    requests.extend({"jsonrpc": "2.0", "id": i + 3, "method": "tools/call", "params": {
        "name": "enrich_ua", "arguments": {"user_agent": ua}}}
                    for i, ua in enumerate(agents))
    payload = b"".join((json.dumps(req, separators=(",", ":")) + "\n").encode()
                   for req in requests)
    with tempfile.TemporaryDirectory(prefix="rg-ua-risk-") as cwd:
        result = subprocess.run(
            [str(binary), "--stdio"], input=payload, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd,
            env={"PATH": os.environ.get("PATH", ""), "HOME": cwd},
            timeout=20, check=False)
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, len(requests) + 1)):
        raise AssertionError("unexpected stdio response count/order")
    for ua, response in zip(agents[:3], responses[2:5]):
        data = response["result"]["structuredContent"]
        if data.get("user_agent") != ua or data.get("risk_score", -1) < 0.7:
            raise AssertionError(f"known scanner got low diagnostic score: {ua}")
    browser = responses[5]["result"]["structuredContent"]
    if browser.get("risk_score") != 0.1 or browser.get("is_bot") is not False:
        raise AssertionError("ordinary browser baseline changed")
    tool = next(tool for tool in responses[1]["result"]["tools"] if tool["name"] == "enrich_ua")
    if "diagnostic risk score" not in tool["description"]:
        raise AssertionError("tools/list omitted the diagnostic risk limitation")
    print("PASS packaged enrich_ua: scanners raised, browser baseline preserved")


if __name__ == "__main__":
    main()
