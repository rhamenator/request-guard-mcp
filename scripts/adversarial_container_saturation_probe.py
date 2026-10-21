#!/usr/bin/env python3
"""Bounded slow-header saturation against an authorized two-slot container."""

import argparse
import json
import socket
import sys
import time

from adversarial_probe import post, rpc
from adversarial_sustained_exhaustion_probe import host_load_1m, io_psi, rss_kib


def ping(url, token):
    status, body = post(url, token, rpc("ping"))
    return status == 200 and json.loads(body).get("result") == {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid", type=int, required=True,
                        help="host PID of the running container's server process")
    parser.add_argument("--cycles", type=int, default=12)
    parser.add_argument("--attempts", type=int, default=32)
    parser.add_argument("--hold-seconds", type=float, default=5.0)
    args = parser.parse_args()
    if not (1 <= args.cycles <= 12 and 1 <= args.attempts <= 32
            and 0.5 <= args.hold_seconds <= 5.0):
        parser.error("bounds: cycles 1..12, attempts 1..32, hold-seconds 0.5..5")
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a synthetic lab bearer token of at least 32 characters from stdin")
    url = f"http://{args.host}:{args.port}"
    started = time.monotonic()
    psi_before = io_psi()
    rss_before = rss_kib(args.pid)
    peak_rss = rss_before
    results = []
    for cycle in range(args.cycles):
        held = []
        shed = 0
        errors = 0
        max_latency = 0.0
        cycle_peak_rss = rss_kib(args.pid)
        try:
            for _ in range(2):
                connection = socket.create_connection((args.host, args.port), timeout=2)
                connection.sendall(b"POST /mcp HTTP/1.1\r\nHost: lab\r\n")
                held.append(connection)
            time.sleep(0.2)
            for _ in range(args.attempts):
                then = time.monotonic()
                try:
                    with socket.create_connection((args.host, args.port), timeout=2) as connection:
                        connection.settimeout(2)
                        try:
                            if connection.recv(1) == b"":
                                shed += 1
                        except ConnectionResetError:
                            shed += 1
                except OSError:
                    errors += 1
                max_latency = max(max_latency, time.monotonic() - then)
                cycle_peak_rss = max(cycle_peak_rss, rss_kib(args.pid))
                time.sleep(args.hold_seconds / args.attempts)
        finally:
            for connection in held:
                connection.close()
        recovered = False
        for _ in range(10):
            try:
                if ping(url, token):
                    recovered = True
                    break
            except (OSError, ValueError, TypeError):
                pass
            time.sleep(0.1)
        results.append({"cycle": cycle + 1, "shed": shed,
                        "attempted": args.attempts, "errors": errors,
                        "recovered": recovered,
                        "max_latency_ms": round(max_latency * 1000, 2),
                        "rss_kib": rss_kib(args.pid),
                        "peak_rss_kib": cycle_peak_rss,
                        "io_psi_some_avg10": io_psi(),
                        "host_load_1m": host_load_1m()})
        peak_rss = max(peak_rss, cycle_peak_rss)
    rss_after = rss_kib(args.pid)
    passed = all(row["shed"] == args.attempts and row["errors"] == 0
                 and row["recovered"] and row["max_latency_ms"] < 2000
                 for row in results) and peak_rss - rss_before < 16384
    print(json.dumps({"case": "container_slow_header_saturation", "pass": passed,
                      "elapsed_seconds": round(time.monotonic() - started, 2),
                      "rss_before_kib": rss_before, "rss_after_kib": rss_after,
                      "peak_rss_kib": peak_rss,
                      "io_psi_some_avg10_before": psi_before,
                      "io_psi_some_avg10_after": io_psi(), "cycles": results}),
          flush=True)
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
