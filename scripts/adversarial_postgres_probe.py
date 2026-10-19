#!/usr/bin/env python3
"""Check a controlled PostgreSQL outage against an authenticated MCP server."""

import argparse
import json
import sys

from adversarial_probe import post


def call(url, token, name, arguments):
    envelope = {"jsonrpc": "2.0", "id": 1, "method": "ping"} if name == "ping" else {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    status, body = post(url, token, json.dumps(envelope).encode())
    return status, json.loads(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--stage", choices=("healthy", "outage"), required=True)
    parser.add_argument("--request-id", default="postgres-lab-001")
    args = parser.parse_args()
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a synthetic lab bearer token of at least 32 characters from stdin")

    checks = []
    for name, arguments in (
        ("classify", {
            "request_id": args.request_id,
            "user_agent": "Mozilla/5.0",
            "path": "/welcome",
            "method": "GET",
        }),
        ("replay_decision", {"request_id": args.request_id}),
        ("ping", {}),
    ):
        try:
            status, response = call(args.url, token, name, arguments)
            if name == "ping":
                passed = status == 200 and response.get("result") == {}
            elif args.stage == "outage":
                error = response.get("error", {})
                passed = status == 200 and error.get("code") == -502 and error.get("message") == "UPSTREAM_ERROR"
            else:
                result = response.get("result", {})
                content = result.get("content", [])
                payload = json.loads(content[0]["text"]) if content else {}
                passed = status == 200 and result.get("isError") is False
                if name == "classify":
                    passed = passed and payload.get("request_id") == args.request_id
                else:
                    passed = passed and payload.get("matches_original") is True
            checks.append(passed)
            print(json.dumps({"stage": args.stage, "tool": name, "pass": passed, "http": status,
                              "error_code": response.get("error", {}).get("code")}))
        except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
            checks.append(False)
            print(json.dumps({"stage": args.stage, "tool": name, "pass": False,
                              "exception": type(error).__name__}))
    print(json.dumps({"passed": sum(checks), "total": len(checks)}))
    raise SystemExit(0 if all(checks) else 1)


if __name__ == "__main__":
    main()
