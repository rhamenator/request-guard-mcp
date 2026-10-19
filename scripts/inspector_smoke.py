#!/usr/bin/env python3
"""Run the pinned official MCP Inspector against a locally installed server binary.

Requires Node.js/npm and network access or an npm cache containing Inspector 2.5.0.
No application credentials or backend services are needed; a temporary test token
is generated for the loopback listener.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


INSPECTOR = "@modelcontextprotocol/inspector@2.5.0"


def free_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def inspector(url: str, token: str, method: str, *args: str) -> dict:
    command = [
        "npx", "--yes", INSPECTOR, "--cli", "--transport", "http",
        "--server-url", url, "--header", f"Authorization: Bearer {token}",
        "--method", method, "--format", "json", *args,
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=90)
    if completed.returncode:
        raise RuntimeError(
            f"Inspector {method} failed ({completed.returncode}): "
            f"{completed.stderr.strip()} {completed.stdout.strip()}"
        )
    return json.loads(completed.stdout)["result"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Installed request-guard-mcp binary")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    token = secrets.token_urlsafe(32)
    port = free_loopback_port()
    url = f"http://127.0.0.1:{port}/mcp"
    env = os.environ.copy()
    env.update({"MCP__HOST": "127.0.0.1", "MCP__PORT": str(port), "AUTH_TOKENS": token})
    # The smoke test must not inherit optional integrations from the operator.
    for key in list(env):
        if key.startswith(("MCP__REDIS__", "MCP__POSTGRES__", "MCP__GEOIP__")):
            del env[key]
    clean_cwd = tempfile.TemporaryDirectory(prefix="request-guard-inspector-")
    server = subprocess.Popen([str(binary)], cwd=clean_cwd.name, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError(f"server exited before readiness: {server.stderr.read()[-2000:]}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1):
                    break
            except (OSError, TimeoutError):
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not become ready")

        initialized = inspector(url, token, "initialize")
        assert initialized["protocolVersion"] == "2025-06-18", initialized
        assert initialized["capabilities"]["tools"]["listChanged"] is False
        print("PASS initialize: 2025-06-18, tools capability")

        listed = inspector(url, token, "tools/list")
        names = {tool["name"] for tool in listed["tools"]}
        assert {"classify", "explain"} <= names, names
        print(f"PASS tools/list: {len(names)} contracts, classify and explain present")

        observed = {"ip": "192.0.2.1", "user_agent": "GPTBot/1.0", "path": "/"}
        classified = inspector(url, token, "tools/call", "--tool-name", "classify",
                               "--tool-args-json", json.dumps(observed))
        assert classified["isError"] is False
        assert classified["structuredContent"]["verdict"] in {"allow", "challenge", "block"}
        print("PASS tools/call classify: structured verdict")

        explained = inspector(url, token, "tools/call", "--tool-name", "explain",
                              "--tool-args-json", json.dumps({"classification": observed}))
        assert explained["isError"] is False
        assert explained["structuredContent"]["factors"]
        print("PASS tools/call explain: contributing factors")
    finally:
        server.terminate()
        try:
            server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.communicate()
        clean_cwd.cleanup()


if __name__ == "__main__":
    main()
