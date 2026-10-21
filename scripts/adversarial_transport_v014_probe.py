#!/usr/bin/env python3
"""Bounded MCP 2025-06-18 HTTP transport checks for an authorized lab."""

import argparse
import ipaddress
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def send(base, token, *, method="POST", body=None, headers=None, authorize=True):
    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if authorize:
        request_headers["Authorization"] = "Bearer " + token
    request_headers.update(headers or {})
    request = urllib.request.Request(
        base.rstrip("/") + "/mcp", data=body, headers=request_headers, method=method
    )
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(
            request, timeout=5
        ) as response:
            return response.status, response.read(65537), response.headers
    except urllib.error.HTTPError as error:
        try:
            return error.code, error.read(65537), error.headers
        finally:
            error.close()


def rpc(method="ping", *, request_id=1, params=None):
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return json.dumps(message).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    endpoint = urllib.parse.urlsplit(args.url)
    try:
        address = ipaddress.ip_address(endpoint.hostname or "")
        port = endpoint.port
    except ValueError:
        parser.error("--url must name a numeric lab IP address and port")
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
        parser.error("--url must be an HTTP endpoint on a private or loopback lab IP and port")
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a synthetic lab bearer token of at least 32 characters")

    checks = []

    def check(name, passed, status):
        checks.append(passed)
        print(json.dumps({"case": name, "pass": bool(passed), "http": status}))

    status, body, _ = send(args.url, token, body=rpc(), authorize=False)
    check("missing_bearer", status == 401 and body == b"UNAUTHENTICATED", status)
    status, body, _ = send(args.url, token + "wrong", body=rpc())
    check("wrong_bearer", status == 403 and body == b"FORBIDDEN", status)
    status, body, _ = send(args.url, token, body=rpc())
    check("authorized_ping", status == 200 and json.loads(body).get("result") == {}, status)
    status, body, _ = send(
        args.url, token, body=rpc(), headers={"Origin": "https://untrusted.example"}
    )
    check("unlisted_origin", status == 403 and body == b"", status)
    status, body, _ = send(
        args.url, token, body=rpc(), headers={"MCP-Protocol-Version": "2024-11-05"}
    )
    check(
        "unsupported_protocol_header",
        status == 400 and body == b"Invalid or unsupported MCP-Protocol-Version",
        status,
    )
    status, body, _ = send(args.url, token, body=rpc(), headers={"Content-Type": "text/plain"})
    check(
        "non_json_content_type",
        status == 415 and body == b"MCP POST Content-Type must be application/json with UTF-8 charset",
        status,
    )
    status, body, _ = send(args.url, token, body=rpc(), headers={"Accept": "text/plain"})
    check(
        "json_excluded_by_accept",
        status == 406 and body == b"MCP HTTP responses require an Accept range allowing application/json",
        status,
    )
    status, body, headers = send(args.url, token, method="GET")
    allowed = {method.strip().upper() for method in headers.get("Allow", "").split(",")}
    check(
        "non_upgrade_get",
        status == 405 and body == b"" and {"POST", "GET"} <= allowed,
        status,
    )
    notification = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
    status, body, _ = send(args.url, token, body=notification)
    check("accepted_notification", status == 202 and body == b"", status)
    bad_notification = json.dumps({
        "jsonrpc": "2.0", "method": "notifications/initialized", "params": []
    }).encode()
    status, body, _ = send(args.url, token, body=bad_notification)
    check("invalid_notification", status == 400 and body == b"", status)
    status, body, _ = send(args.url, token, body=rpc(request_id=99))
    check("post_rejection_recovery", status == 200 and json.loads(body).get("id") == 99, status)
    print(json.dumps({"passed": sum(checks), "total": len(checks)}))
    raise SystemExit(0 if all(checks) else 1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"pass": False, "fatal": type(error).__name__}))
        raise SystemExit(1)
