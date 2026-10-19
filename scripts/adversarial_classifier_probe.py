#!/usr/bin/env python3
"""Bounded classifier-evasion probe against an authorized MCP HTTP endpoint."""

import argparse
import json
import sys

from adversarial_probe import post


CASES = (
    ("benign_browser", "Mozilla/5.0", "/welcome", None, {"ua_ai_bot", "path_sensitive"}),
    ("gptbot_casefold", "gPtBoT/1.0", "/welcome", "ua_ai_bot", set()),
    ("gptbot_embedded", "Mozilla/5.0 (compatible; GPTBot/1.0)", "/welcome", "ua_ai_bot", set()),
    ("raw_dotenv", "Mozilla/5.0", "/.env", "path_sensitive", set()),
    ("encoded_dotenv", "Mozilla/5.0", "/%2eenv", "path_sensitive", set()),
    ("double_encoded_dotenv", "Mozilla/5.0", "/%252eenv", "path_sensitive", set()),
    ("encoded_separator", "Mozilla/5.0", "/%2fadmin", "path_sensitive", set()),
    ("double_encoded_backslash", "Mozilla/5.0", "/%255cadmin", "path_sensitive", set()),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8085")
    args = parser.parse_args()
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a lab bearer token of at least 32 characters from stdin")

    results = []
    for request_id, (name, user_agent, path, required, absent) in enumerate(CASES, 1):
        envelope = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": "classify",
                "arguments": {"user_agent": user_agent, "path": path, "method": "GET"},
            },
        }
        status, body = post(args.url, token, json.dumps(envelope).encode())
        try:
            message = json.loads(body)
            result = message["result"]
            names = {signal["name"] for signal in result["structuredContent"]["signals"]}
            passed = (
                status == 200
                and message["id"] == request_id
                and result["isError"] is False
                and (required is None or required in names)
                and not (absent & names)
                and token.encode() not in body
            )
        except (KeyError, TypeError, ValueError):
            names = set()
            passed = False
        results.append(passed)
        print(json.dumps({"case": name, "pass": passed, "http": status, "signals": sorted(names)}))

    print(json.dumps({"passed": sum(results), "total": len(results)}))
    raise SystemExit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
