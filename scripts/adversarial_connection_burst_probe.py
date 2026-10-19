#!/usr/bin/env python3
"""Bounded connection shedding and recovery against a two-slot lab listener."""

import argparse
import json
import socket
import sys
import time

from adversarial_probe import post, rpc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--attempts", type=int, default=128)
    args = parser.parse_args()
    if not 1 <= args.attempts <= 256:
        parser.error("--attempts must be 1..256")
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a lab bearer token of at least 32 characters from stdin")

    held = []
    shed = 0
    errors = 0
    max_latency = 0.0
    try:
        for _ in range(2):
            connection = socket.create_connection((args.host, args.port), timeout=2)
            connection.sendall(b"POST /mcp HTTP/1.1\r\nHost: lab\r\n")
            held.append(connection)
        time.sleep(0.1)
        for _ in range(args.attempts):
            start = time.monotonic()
            try:
                with socket.create_connection((args.host, args.port), timeout=2) as connection:
                    connection.settimeout(2)
                    try:
                        closed = connection.recv(1) == b""
                    except ConnectionResetError:
                        closed = True
                    if closed:
                        shed += 1
            except OSError:
                errors += 1
            max_latency = max(max_latency, time.monotonic() - start)
    finally:
        for connection in held:
            connection.close()

    try:
        status, response = post(
            f"http://{args.host}:{args.port}", token, rpc("ping")
        )
        recovered = status == 200 and json.loads(response).get("result") == {}
    except (OSError, ValueError, TypeError):
        recovered = False
    passed = (
        shed == args.attempts and errors == 0 and recovered and max_latency < 2
    )
    print(json.dumps({
        "case": "bounded_connection_burst",
        "pass": passed,
        "shed": shed,
        "attempted": args.attempts,
        "exceptions": errors,
        "max_latency_ms": round(max_latency * 1000, 2),
        "recovered": recovered,
    }), flush=True)
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
