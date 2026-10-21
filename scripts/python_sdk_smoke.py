#!/usr/bin/env python3
"""Probe an installed Request Guard binary with the official Python MCP SDK.

In a disposable virtual environment: pip install 'mcp==2.3.0'
Then: python scripts/python_sdk_smoke.py --binary /path/to/request-guard-mcp
No external listener or configured backend is used.
"""

import argparse
import asyncio
import os
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request
from urllib.error import HTTPError
from pathlib import Path

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


async def probe(url, token, expected_version):
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=10.0) as client:
        async with streamable_http_client(url, http_client=client) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                initialized = await session.initialize()
                require(initialized.protocol_version == "2025-06-18", "unexpected protocol version")
                if expected_version:
                    require(initialized.server_info.version == expected_version, "unexpected server version")
                listed = await session.list_tools()
                require({"classify", "explain"} <= {tool.name for tool in listed.tools}, "core tools missing")
                result = await session.call_tool("classify", {
                    "ip": "192.0.2.1", "user_agent": "GPTBot/1.0", "path": "/",
                })
                require(not result.is_error, "classify returned tool error")
                require(result.structured_content["verdict"] == "block", "unexpected verdict")
                require(result.structured_content["threat_category"] == "ai_scraping", "unexpected category")
                print("PASS Python MCP SDK: initialize, tools/list, classify")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected-version")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    token = secrets.token_urlsafe(32)
    port = free_port()
    essentials = {"PATH", "TMPDIR"}
    env = {key: value for key, value in os.environ.items() if key.upper() in essentials}
    env.update({"MCP__HOST": "127.0.0.1", "MCP__PORT": str(port),
                "MCP__AUTH__ENABLED": "true", "AUTH_TOKENS": token})
    with tempfile.TemporaryDirectory(prefix="request-guard-python-sdk-") as cwd:
        env["HOME"] = cwd
        server = subprocess.Popen([str(binary)], cwd=cwd, env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("server exited before readiness")
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                    break
                except (OSError, TimeoutError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("server did not become ready")
            unauthenticated = urllib.request.Request(
                f"http://127.0.0.1:{port}/mcp",
                data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                headers={"Content-Type": "application/json",
                         "Accept": "application/json, text/event-stream"},
            )
            try:
                urllib.request.urlopen(unauthenticated, timeout=5)
            except HTTPError as error:
                require(error.code == 401, f"expected 401 without bearer, got {error.code}")
            else:
                raise RuntimeError("server accepted a request without bearer token")
            require(server.poll() is None, "server exited during readiness check")
            asyncio.run(probe(f"http://127.0.0.1:{port}/mcp", token, args.expected_version))
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


if __name__ == "__main__":
    main()
