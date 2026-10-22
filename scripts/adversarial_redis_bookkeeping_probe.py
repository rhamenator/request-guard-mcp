#!/usr/bin/env python3
"""Bounded Linux/Docker lab probe for Redis bookkeeping outage latency.

Run only against an owned binary and isolated test ports. The bearer token is
synthetic; the script prints response shape and timing, never the token.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def docker(*args):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout.strip()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def rpc(port, token, method, params=None, timeout_secs=5):
    envelope = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        envelope["params"] = params
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp",
        data=json.dumps(envelope).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    started = time.monotonic()
    with urllib.request.urlopen(request, timeout=timeout_secs) as response:
        value = json.load(response)
        elapsed = time.monotonic() - started
        result = value.get("result", {})
        return elapsed, response.status, result.get("isError"), value.get("error", {}).get("code")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--redis-image", default="redis:7.2-alpine")
    parser.add_argument("--redis-port", type=int)
    parser.add_argument("--mcp-port", type=int)
    parser.add_argument("--max-seconds", type=float, default=1.8,
                        help="maximum median paused-classify latency")
    parser.add_argument("--max-worst-seconds", type=float, default=2.25)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error("binary does not exist")
    if args.repeats < 1:
        parser.error("repeats must be positive")
    redis_port = args.redis_port or free_port()
    mcp_port = args.mcp_port or free_port()
    if redis_port == mcp_port:
        parser.error("Redis and MCP ports must differ")

    name = f"request-guard-redis-bookkeeping-{uuid.uuid4().hex[:12]}"
    workdir = tempfile.TemporaryDirectory(prefix="request-guard-redis-probe-")
    token = "x" * 64
    # Exclude unrelated host MCP__*, database and telemetry configuration.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.update(
        AUTH_TOKENS=token,
        MCP__HOST="127.0.0.1",
        MCP__PORT=str(mcp_port),
        MCP__REDIS__URL=f"redis://127.0.0.1:{redis_port}/",
        MCP__LIMITS__CLASSIFY_TIMEOUT_SECS="2",
        MCP__LIMITS__PER_TOOL_TIMEOUT_SECS="2",
    )
    process = None
    paused = False
    try:
        docker(
            "run", "--rm", "-d", "--name", name, "--network", "host",
            args.redis_image, "redis-server", "--bind", "127.0.0.1",
            "--port", str(redis_port), "--save", "", "--appendonly", "no",
        )
        for _ in range(50):
            try:
                if docker("exec", name, "redis-cli", "-h", "127.0.0.1",
                          "-p", str(redis_port), "PING") == "PONG":
                    break
            except subprocess.CalledProcessError:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("test Redis did not become ready")
        process = subprocess.Popen(
            [str(args.binary.resolve())], cwd=workdir.name, env=env, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(60):
            if process.poll() is not None:
                raise RuntimeError("server exited during startup")
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{mcp_port}/health", timeout=0.3
                ) as response:
                    health = json.load(response)
                    if response.status == 200 and health.get("checks", {}).get("redis", {}).get("status") == "healthy":
                        break
            except (OSError, urllib.error.URLError, ValueError):
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("server did not become healthy")

        classify = {"name": "classify", "arguments": {
            "ip": "198.51.100.25", "user_agent": "Mozilla/5.0",
            "method": "GET", "path": "/test",
        }}
        healthy = rpc(mcp_port, token, "tools/call", classify)
        docker("pause", name)
        paused = True
        outages = [rpc(mcp_port, token, "tools/call", classify, timeout_secs=8)
                   for _ in range(args.repeats)]
        ping = rpc(mcp_port, token, "ping", timeout_secs=2)
        median_seconds = statistics.median(outage[0] for outage in outages)
        worst_seconds = max(outage[0] for outage in outages)
        print(json.dumps({
            "healthy_classify_seconds": round(healthy[0], 3),
            "paused_classify_seconds": [round(outage[0], 3) for outage in outages],
            "paused_classify_median_seconds": round(median_seconds, 3),
            "paused_classify_worst_seconds": round(worst_seconds, 3),
            "paused_classify_http": [outage[1] for outage in outages],
            "paused_classify_is_error": [outage[2] for outage in outages],
            "paused_ping_http": ping[1],
            "redis_image": args.redis_image,
        }))
        if not (healthy[1:] == (200, False, None)
                and all(outage[1:] == (200, False, None) for outage in outages)
                and ping[1:] == (200, None, None)
                and median_seconds < args.max_seconds
                and worst_seconds < args.max_worst_seconds):
            raise RuntimeError("Redis outage exceeded latency or response-shape gate")
    finally:
        if paused:
            subprocess.run(["docker", "unpause", name], capture_output=True)
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        subprocess.run(["docker", "stop", name], capture_output=True)
        workdir.cleanup()


if __name__ == "__main__":
    main()
