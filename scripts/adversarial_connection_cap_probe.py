#!/usr/bin/env python3
"""Bounded connection-cap probe for an authorized loopback Request Guard lab."""

import argparse
import json
import socket
import sys
import time

from adversarial_probe import post, rpc


def check(name, passed, detail):
    print(json.dumps({"case": name, "pass": passed, "detail": detail}), flush=True)
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a lab bearer token of at least 32 characters from stdin")

    held = []
    results = []
    try:
        for _ in range(2):
            connection = socket.create_connection((args.host, args.port), timeout=3)
            connection.settimeout(3)
            connection.sendall(
                f"POST /mcp HTTP/1.1\r\nHost: {args.host}:{args.port}\r\n".encode()
            )
            held.append(connection)
        # A partial HTTP header keeps each permit occupied until its read deadline.
        time.sleep(0.2)
        both_held = True
        for connection in held:
            connection.settimeout(0.2)
            try:
                connection.recv(1, socket.MSG_PEEK)
                both_held = False
            except socket.timeout:
                pass
            except OSError:
                both_held = False
        results.append(check("connection_cap_holds_two", both_held, "pending" if both_held else "closed_or_replied"))
        if both_held:
            with socket.create_connection((args.host, args.port), timeout=3) as excess:
                excess.settimeout(3)
                try:
                    rejected = excess.recv(1) == b""
                except ConnectionResetError:
                    rejected = True
            results.append(check("connection_cap_sheds_third", rejected, "closed" if rejected else "open"))
        else:
            results.append(check("connection_cap_sheds_third", False, "slots_not_held"))
    except OSError as error:
        if len(results) == 0:
            results.append(check("connection_cap_holds_two", False, type(error).__name__))
        results.append(check("connection_cap_sheds_third", False, type(error).__name__))
    finally:
        for connection in held:
            connection.close()

    recovered = False
    for _ in range(10):
        try:
            status, response = post(
                f"http://{args.host}:{args.port}", token, rpc("ping")
            )
            recovered = status == 200 and json.loads(response).get("result") == {}
            if recovered:
                break
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    results.append(check("connection_cap_recovers", recovered, "ping" if recovered else "no_ping"))
    print(json.dumps({"passed": sum(results), "total": len(results)}))
    raise SystemExit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
