#!/usr/bin/env python3
"""Check a seeded Redis lookup through a controlled outage on an owned lab server."""

import argparse
import json
import sys

from adversarial_probe import post


def call(url, token, name, arguments):
    envelope = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}}
    status, body = post(url, token, json.dumps(envelope).encode())
    return status, json.loads(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--stage", choices=("healthy", "outage"), required=True)
    parser.add_argument("--indicator", required=True)
    parser.add_argument("--source", default="request_guard_lab")
    args = parser.parse_args()
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a synthetic lab bearer token of at least 32 characters from stdin")

    checks = []
    for name, arguments in (
        ("threat_lookup", {"indicator": args.indicator}),
        ("classify", {"ip": "192.0.2.1", "user_agent": "Mozilla/5.0",
                      "path": "/health-check"}),
    ):
        try:
            status, response = call(args.url, token, name, arguments)
            if name == "threat_lookup" and args.stage == "outage":
                error = response.get("error", {})
                passed = (status == 200 and error.get("code") == -502
                          and error.get("message") == "UPSTREAM_ERROR")
            else:
                result = response.get("result", {})
                passed = status == 200 and result.get("isError") is False
                if name == "threat_lookup":
                    record = result.get("structuredContent", {})
                    passed = (passed and record.get("found") is True
                              and record.get("source") == args.source)
            checks.append(passed)
            print(json.dumps({"stage": args.stage, "tool": name, "pass": passed,
                              "http": status,
                              "error_code": response.get("error", {}).get("code")}))
        except (OSError, ValueError, KeyError, IndexError, TypeError,
                AttributeError) as error:
            checks.append(False)
            print(json.dumps({"stage": args.stage, "tool": name, "pass": False,
                              "exception": type(error).__name__}))
    print(json.dumps({"passed": sum(checks), "total": len(checks)}))
    raise SystemExit(0 if all(checks) else 1)


if __name__ == "__main__":
    main()
