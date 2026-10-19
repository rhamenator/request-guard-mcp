#!/usr/bin/env python3
"""Run twelve bounded slow-header saturation cycles against a loopback lab server."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

from ci_adversarial_smoke import unused_loopback_port, wait_for_health
from adversarial_probe import post, rpc

CYCLES = 12
ATTEMPTS_PER_CYCLE = 32
HOLD_SECONDS = 5


def rss_kib(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise RuntimeError("server RSS unavailable")


def io_psi():
    return Path("/proc/pressure/io").read_text().splitlines()[0].split()[1]


def host_load_1m():
    return float(Path("/proc/loadavg").read_text().split()[0])


def ping(port, token):
    status, response = post(f"http://127.0.0.1:{port}", token, rpc("ping"))
    return status == 200 and json.loads(response).get("result") == {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    port = unused_loopback_port()
    token = secrets.token_urlsafe(48)
    env = os.environ.copy()
    for name in ("CONFIG_FILE", "MCP__REDIS__URL", "MCP__POSTGRES__URL"):
        env.pop(name, None)
    env.update({
        "AUTH_TOKENS": token,
        "MCP__AUTH__ENABLED": "true",
        "MCP__HOST": "127.0.0.1",
        "MCP__PORT": str(port),
        "MCP__LIMITS__MAX_CONNECTIONS": "2",
        "MCP__LIMITS__HTTP_HEADER_TIMEOUT_SECS": "10",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    })
    results = []
    started = time.monotonic()
    psi_before = io_psi()
    with tempfile.TemporaryDirectory() as directory:
        process = subprocess.Popen([str(binary)], cwd=directory, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for_health(process, port)
            rss_before = rss_kib(process.pid)
            for cycle in range(CYCLES):
                held = []
                shed = 0
                errors = 0
                max_latency = 0.0
                try:
                    for _ in range(2):
                        connection = socket.create_connection(("127.0.0.1", port), timeout=2)
                        connection.sendall(b"POST /mcp HTTP/1.1\r\nHost: lab\r\n")
                        held.append(connection)
                    time.sleep(0.2)
                    for _ in range(ATTEMPTS_PER_CYCLE):
                        then = time.monotonic()
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                                connection.settimeout(2)
                                try:
                                    if connection.recv(1) == b"":
                                        shed += 1
                                except ConnectionResetError:
                                    shed += 1
                        except OSError:
                            errors += 1
                        max_latency = max(max_latency, time.monotonic() - then)
                        time.sleep(HOLD_SECONDS / ATTEMPTS_PER_CYCLE)
                finally:
                    for connection in held:
                        connection.close()
                recovered = False
                for _ in range(10):
                    try:
                        if ping(port, token):
                            recovered = True
                            break
                    except (OSError, ValueError, TypeError):
                        pass
                    time.sleep(0.1)
                results.append({"cycle": cycle + 1, "shed": shed,
                                "attempted": ATTEMPTS_PER_CYCLE,
                                "errors": errors, "recovered": recovered,
                                "max_latency_ms": round(max_latency * 1000, 2),
                                "rss_kib": rss_kib(process.pid),
                                "io_psi_some_avg10": io_psi(),
                                "host_load_1m": host_load_1m()})
            rss_after = rss_kib(process.pid)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    passed = all(r["shed"] == ATTEMPTS_PER_CYCLE and r["errors"] == 0
                 and r["recovered"] and r["max_latency_ms"] < 2000
                 for r in results) and rss_after - rss_before < 16384
    print(json.dumps({"case": "sustained_slow_header_saturation", "pass": passed,
                      "binary_sha256": digest, "elapsed_seconds": round(time.monotonic() - started, 2),
                      "rss_before_kib": rss_before, "rss_after_kib": rss_after,
                      "io_psi_some_avg10_before": psi_before,
                      "io_psi_some_avg10_after": io_psi(), "cycles": results}), flush=True)
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
