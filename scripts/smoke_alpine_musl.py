#!/usr/bin/env python3
"""Exercise a packaged musl server inside Alpine through its MCP HTTP API."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error
import urllib.request

ALPINE_IMAGE = "docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"


def call(url: str, token: str | None, method: str, params: dict | None = None) -> dict:
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--port", type=int, default=18767)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    token = secrets.token_hex(32)
    name = f"request-guard-musl-smoke-{os.getpid()}"
    # Docker Official Image index digest; refresh with:
    # docker buildx imagetools inspect docker.io/library/alpine:3.24.2
    image = ALPINE_IMAGE
    command = [
        "docker", "run", "--rm", "--name", name, "--network", "host",
        "--read-only", "--tmpfs", "/tmp", "--mount",
        f"type=bind,src={binary},dst=/usr/local/bin/request-guard-mcp,readonly",
        "-e", f"AUTH_TOKENS={token}", "-e", "MCP__HOST=127.0.0.1",
        "-e", f"MCP__PORT={args.port}",
        # Exporter initialization must accept HTTPS even without a collector
        # in this bounded container smoke. The VM integration test exercises
        # certificate trust and a receiving collector separately.
        "-e", "MCP__TELEMETRY__OTLP_ENDPOINT=https://localhost:4318", image,
        "/usr/local/bin/request-guard-mcp",
    ]
    server = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{args.port}/mcp"
    try:
        for _ in range(200):
            if server.poll() is not None:
                raise RuntimeError(
                    f"musl binary exited inside Alpine before health became ready: {server.returncode}"
                )
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{args.port}/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except (OSError, TimeoutError):
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("musl binary in Alpine did not become healthy")

        try:
            call(url, None, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                            "clientInfo": {"name": "alpine-smoke", "version": "1"}})
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise RuntimeError(f"missing token returned HTTP {error.code}") from error
        else:
            raise RuntimeError("missing token was accepted")

        initialized = call(url, token, "initialize", {"protocolVersion": "2025-06-18",
                                                       "capabilities": {},
                                                       "clientInfo": {"name": "alpine-smoke", "version": "1"}})["result"]
        if initialized["protocolVersion"] != "2025-06-18":
            raise RuntimeError("unexpected MCP protocol version")
        if initialized["serverInfo"]["version"] != args.expected_version:
            raise RuntimeError("server version differs from Cargo package")
        tools = call(url, token, "tools/list")["result"]["tools"]
        if not {"classify", "explain"} <= {tool["name"] for tool in tools}:
            raise RuntimeError("core tools are missing")
        classified = call(url, token, "tools/call", {"name": "classify", "arguments": {
            "ip": "192.0.2.1", "user_agent": "GPTBot/1.0", "path": "/"}})["result"]
        if classified.get("isError") is not False:
            raise RuntimeError("classify returned an MCP tool error")
        if classified.get("structuredContent", {}).get("verdict") not in {"allow", "challenge", "block"}:
            raise RuntimeError("classify omitted a structured verdict")
        print("PASS Alpine musl: health, authentication, initialize, tools/list, classify")
    finally:
        subprocess.run(["docker", "stop", "--time", "2", name], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


if __name__ == "__main__":
    main()
