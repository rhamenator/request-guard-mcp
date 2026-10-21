#!/usr/bin/env python3
"""Bounded cloud-proxy -> Request Guard classify probe using synthetic data."""
import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_healthy(port, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(f"service exited before health check: {process.returncode}")
        try:
            with OPENER.open(f"http://127.0.0.1:{port}/health", timeout=0.2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    raise RuntimeError("service health check timed out")


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request_guard_binary")
    parser.add_argument("cloud_proxy_binary")
    parser.add_argument("--guard-sha256", help="Expected SHA256 of the Request Guard binary")
    args = parser.parse_args()
    if args.guard_sha256:
        with open(args.request_guard_binary, "rb") as binary:
            actual = hashlib.file_digest(binary, "sha256").hexdigest()
        if actual.lower() != args.guard_sha256.lower():
            raise RuntimeError("Request Guard binary SHA256 mismatch")
    guard_port, proxy_port = free_port(), free_port()
    if guard_port == proxy_port:
        raise RuntimeError("ephemeral port collision; retry")
    guard_token = secrets.token_hex(32)
    proxy_key = secrets.token_hex(32)
    base_env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
    guard_env = dict(base_env, MCP__HOST="127.0.0.1", MCP__PORT=str(guard_port), AUTH_TOKENS=guard_token)
    proxy_env = dict(
        base_env,
        CLOUD_PROXY_PORT=str(proxy_port),
        CLOUD_PROXY_API_KEY=proxy_key,
        MODEL_URI="mcp://primary/classify",
        MCP_SERVER_PRIMARY_TRANSPORT="ws",
        MCP_SERVER_PRIMARY_URL=f"ws://127.0.0.1:{guard_port}/mcp",
        MCP_SERVER_PRIMARY_AUTH_TOKEN=guard_token,
        MCP_SERVER_PRIMARY_TIMEOUT="5",
    )
    guard = subprocess.Popen([args.request_guard_binary], env=guard_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = None
    try:
        wait_healthy(guard_port, guard)
        proxy = subprocess.Popen([args.cloud_proxy_binary], env=proxy_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_healthy(proxy_port, proxy)
        body = json.dumps({"ip": "192.0.2.42", "user_agent": "GPTBot/1.0", "path": "/robots.txt", "method": "GET"}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{proxy_port}/api/chat",
            body,
            headers={"Content-Type": "application/json", "x-api-key": proxy_key},
            method="POST",
        )
        with OPENER.open(request, timeout=8) as response:
            data = json.load(response)
        result = data.get("response", {})
        signals = {entry.get("name") for entry in result.get("signals", [])}
        if data.get("status") != "success" or data.get("provider") != "mcp":
            raise RuntimeError("cloud-proxy did not use the MCP provider successfully")
        if result.get("verdict") != "block" or not {"ua_ai_bot", "ua_non_browser"} <= signals:
            raise RuntimeError("Request Guard did not return the expected bot classification")
        score = result.get("score")
        if not isinstance(score, (int, float)) or abs(score - 0.9181818181818181) > 1e-9:
            raise RuntimeError("Request Guard returned an unexpected score")
        print(f"PASS: MCP block, score={score}, signals={sorted(signals)}")
    finally:
        for process in (proxy, guard):
            stop(process)


if __name__ == "__main__":
    main()
