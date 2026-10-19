#!/usr/bin/env python3
"""Bounded slow-client and body-limit probe for an authorized loopback lab."""

import argparse
import json
import socket
import sys

from adversarial_probe import post, rpc


def raw_status(host, port, payload):
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(payload)
        line = bytearray()
        while not line.endswith(b"\r\n"):
            if len(line) >= 256:
                raise ValueError("HTTP status line exceeded 256 bytes")
            byte = connection.recv(1)
            if not byte:
                return None
            line.extend(byte)
        parts = line.split(b" ", 2)
        if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
            raise ValueError("invalid HTTP status line")
        return int(parts[1])


def check(name, expected, operation):
    try:
        observed = operation()
        passed = observed in expected
        detail = observed
    except (OSError, ValueError) as error:
        passed = False
        detail = type(error).__name__
    print(json.dumps({"case": name, "pass": passed, "detail": detail}))
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--max-request-bytes", type=int, required=True)
    args = parser.parse_args()
    if args.max_request_bytes < 2 or args.max_request_bytes > 65536:
        parser.error("use a lab body limit from 2 to 65536 bytes")
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a lab bearer token of at least 32 characters from stdin")

    host_header = f"Host: {args.host}:{args.port}\r\n".encode()
    authorization = f"Authorization: Bearer {token}\r\n".encode()
    incomplete_headers = b"POST /mcp HTTP/1.1\r\n" + host_header
    incomplete_body = (
        b"POST /mcp HTTP/1.1\r\n"
        + host_header
        + authorization
        + f"Content-Type: application/json\r\nContent-Length: {min(128, args.max_request_bytes)}\r\n\r\nx".encode()
    )
    body = b"x" * (args.max_request_bytes + 1)
    chunked_body = (
        b"POST /mcp HTTP/1.1\r\n"
        + host_header
        + authorization
        + b"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
        + f"{len(body):x}\r\n".encode()
        + body
        + b"\r\n0\r\n\r\n"
    )

    results = [
        check(
            "incomplete_headers_close",
            {None, 400, 408},
            lambda: raw_status(args.host, args.port, incomplete_headers),
        ),
        check(
            "incomplete_body_408",
            {408},
            lambda: raw_status(args.host, args.port, incomplete_body),
        ),
        check(
            "chunked_body_413",
            {413},
            lambda: raw_status(args.host, args.port, chunked_body),
        ),
    ]

    def recovery():
        status, response = post(f"http://{args.host}:{args.port}", token, rpc("ping"))
        value = json.loads(response)
        return status if value.get("result") == {} else -1

    results.append(check("post_limit_recovery", {200}, recovery))
    print(json.dumps({"passed": sum(results), "total": len(results)}))
    raise SystemExit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
