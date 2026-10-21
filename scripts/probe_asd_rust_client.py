#!/usr/bin/env python3
"""Bounded loopback cloud-proxy -> Request Guard classify integration probe."""
import argparse
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_healthy(port, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(f"service exited before health check: {process.returncode}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    raise RuntimeError("service health check timed out")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request_guard_binary")
    parser.add_argument("cloud_proxy_binary")
    args = parser.parse_args()
    guard_port, proxy_port = free_port(), free_port()
    guard_token = "synthetic-rg-token-0123456789abcdef"
    proxy_key = "synthetic-cp-key-0123456789abcdef"
    guard_env = dict(os.environ, MCP__HOST="127.0.0.1", MCP__PORT=str(guard_port), AUTH_TOKENS=guard_token)
    proxy_env = dict(
        os.environ,
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
        with urllib.request.urlopen(request, timeout=8) as response:
            data = json.load(response)
        result = data.get("response", {})
        signals = {entry.get("name") for entry in result.get("signals", [])}
        assert data.get("status") == "success" and data.get("provider") == "mcp", data
        assert result.get("verdict") == "block", result
        assert {"ua_ai_bot", "ua_non_browser"} <= signals, result
        print(f"PASS: MCP block, score={result.get('score')}, signals={sorted(signals)}")
    finally:
        for process in (proxy, guard):
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
