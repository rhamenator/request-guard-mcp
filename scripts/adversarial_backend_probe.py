#!/usr/bin/env python3
"""Probe an unavailable optional backend and healthy core tool on an owned lab endpoint."""

import argparse
import json
import sys

from adversarial_probe import post, rpc


def check(name, passed, detail):
    print(json.dumps({"case": name, "pass": bool(passed), "detail": detail}), flush=True)
    return bool(passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8085")
    args = parser.parse_args()
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a lab bearer token of at least 32 characters from stdin")

    results = []
    unavailable = rpc(
        "tools/call",
        {"name": "threat_lookup", "arguments": {"indicator": "example.com"}},
        request_id=201,
    )
    status, body = post(args.url, token, unavailable)
    value = json.loads(body)
    error = value.get("error", {})
    results.append(check(
        "redis_unavailable_error",
        status == 200 and value.get("id") == 201
        and error.get("code") == -502
        and error.get("message") == "INTEGRATION_UNAVAILABLE"
        and "result" not in value,
        {"http": status, "rpc": error.get("code"), "message": error.get("message")},
    ))

    healthy = rpc(
        "tools/call",
        {"name": "classify", "arguments": {
            "ip": "198.51.100.25", "user_agent": "Mozilla/5.0",
            "method": "GET", "path": "/health-check",
        }},
        request_id=202,
    )
    status, body = post(args.url, token, healthy)
    value = json.loads(body)
    result = value.get("result", {})
    results.append(check(
        "core_tool_after_backend_error",
        status == 200 and value.get("id") == 202
        and result.get("isError") is False
        and isinstance(result.get("structuredContent"), dict),
        {"http": status, "isError": result.get("isError")},
    ))
    print(json.dumps({"passed": sum(results), "total": len(results)}))
    raise SystemExit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
