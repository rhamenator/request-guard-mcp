#!/usr/bin/env python3
"""Check pinned MCP/JSON-RPC envelope cases against an authorized HTTP lab."""

import argparse
import ipaddress
import json
import sys
import urllib.parse

from adversarial_transport_v014_probe import send


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    endpoint = urllib.parse.urlsplit(args.url)
    try:
        address = ipaddress.ip_address(endpoint.hostname or "")
        port = endpoint.port
    except ValueError:
        parser.error("--url must name a numeric private lab IP and port")
    if (
        endpoint.scheme != "http"
        or not (address.is_private or address.is_loopback)
        or not port
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.path not in ("", "/")
        or endpoint.query
        or endpoint.fragment
    ):
        parser.error("--url must be an HTTP endpoint on a private lab IP and port")
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a synthetic bearer token of at least 32 characters")

    cases = [
        ("parse_error", b"{", 200, -32700, None),
        ("array_input", b"[]", 200, -32600, None),
        ("wrong_jsonrpc", b'{"jsonrpc":"1.0","id":1,"method":"ping"}', 200, -32600, None),
        ("null_request_id", b'{"jsonrpc":"2.0","id":null,"method":"ping"}', 200, -32600, None),
        ("fractional_request_id", b'{"jsonrpc":"2.0","id":1.5,"method":"ping"}', 200, -32600, None),
        ("nonobject_params", b'{"jsonrpc":"2.0","id":"known","method":"ping","params":[]}', 200, -32600, "known"),
        ("integer_id", b'{"jsonrpc":"2.0","id":7,"method":"ping"}', 200, None, 7),
        ("string_id", b'{"jsonrpc":"2.0","id":"s","method":"ping"}', 200, None, "s"),
        ("notification", b'{"jsonrpc":"2.0","method":"notifications/initialized"}', 202, None, None),
        ("bad_notification", b'{"jsonrpc":"2.0","method":"notifications/initialized","params":[]}', 400, None, None),
        ("client_response", b'{"jsonrpc":"2.0","id":7,"result":{}}', 202, None, None),
        ("bad_client_result", b'{"jsonrpc":"2.0","id":7,"result":[]}', 400, None, None),
        ("recovery", b'{"jsonrpc":"2.0","id":99,"method":"ping"}', 200, None, 99),
    ]
    passed = 0
    for name, payload, expected_status, expected_error, expected_id in cases:
        try:
            status, body, _ = send(args.url, token, body=payload)
            if status in (202, 400) and expected_status in (202, 400):
                ok = status == expected_status and body == b""
            else:
                response = json.loads(body)
                ok = (
                    status == expected_status
                    and isinstance(response, dict)
                    and response.get("jsonrpc") == "2.0"
                    and "id" in response
                    and response["id"] == expected_id
                    and (
                        response.get("error", {}).get("code") == expected_error
                        if expected_error is not None
                        else response.get("result") == {}
                    )
                )
        except (OSError, ValueError, TypeError, AttributeError):
            ok = False
        passed += ok
        print(json.dumps({"case": name, "pass": ok}), flush=True)
    print(json.dumps({"passed": passed, "total": len(cases)}), flush=True)
    raise SystemExit(0 if passed == len(cases) else 1)


if __name__ == "__main__":
    main()
