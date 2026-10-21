#!/usr/bin/env python3
"""Run the pinned official MCP Inspector against a locally installed server binary.

Requires Node.js/npm and network access or an npm cache containing Inspector 2.11.0.
No application credentials or backend services are needed; a temporary test token
is generated for the loopback listener.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from urllib.error import HTTPError
from pathlib import Path


INSPECTOR_FIXTURE = Path(__file__).with_name("inspector-fixture")
EXPECTED_INSPECTOR_VERSION = "2.11.0"
EXPECTED_CLIENT_VERSION = "2.3.1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def check_node_version() -> None:
    completed = subprocess.run(["node", "--version"], capture_output=True, text=True,
                               timeout=10, check=True)
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", completed.stdout.strip())
    require(match is not None and tuple(map(int, match.groups())) >= (22, 19, 0),
            "MCP Inspector 2.11.0 requires Node.js >=22.19.0")


def free_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def install_inspector(directory: str) -> Path:
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    require(npm is not None, "npm executable was not found")
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(INSPECTOR_FIXTURE / name, Path(directory) / name)
    command = [npm, "ci", "--prefix", directory, "--ignore-scripts",
               "--no-audit", "--no-fund"]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if completed.returncode:
        raise RuntimeError(f"Inspector install failed: {completed.stderr[-1000:]}")
    for package, expected in (("@modelcontextprotocol/inspector", EXPECTED_INSPECTOR_VERSION),
                              ("@modelcontextprotocol/client", EXPECTED_CLIENT_VERSION)):
        installed = Path(directory) / "node_modules" / package / "package.json"
        require(installed.is_file(), f"installed {package} was not found")
        actual = json.loads(installed.read_text())["version"]
        require(actual == expected, f"installed {package} is not the reviewed version")
    launcher = (Path(directory) / "node_modules" / "@modelcontextprotocol" /
                "inspector" / "clients" / "launcher" / "build" / "index.js")
    require(launcher.is_file(), "installed Inspector CLI entrypoint was not found")
    return launcher


def inspector(launcher: Path, url: str, token: str, method: str, *args: str) -> dict:
    command = [
        "node", str(launcher), "--cli", "--transport", "http",
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
    parser.add_argument("--expected-version", help="Expected packaged serverInfo.version")
    parser.add_argument("binary", type=Path, help="Installed request-guard-mcp binary")
    args = parser.parse_args()
    check_node_version()
    binary = args.binary.resolve(strict=True)
    token = secrets.token_urlsafe(32)
    port = free_loopback_port()
    url = f"http://127.0.0.1:{port}/mcp"
    # Pass only process essentials, so operator config cannot disable auth or
    # connect the test server to real optional services.
    essentials = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR",
                  "HOME", "USERPROFILE"}
    env = {key: value for key, value in os.environ.items()
           if key.upper() in essentials}
    env.update({"MCP__HOST": "127.0.0.1", "MCP__PORT": str(port),
                "MCP__AUTH__ENABLED": "true", "AUTH_TOKENS": token})
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

        probe = urllib.request.Request(url, data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                                       headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(probe, timeout=5)
        except HTTPError as error:
            require(error.code == 401, "missing bearer token did not return HTTP 401")
        else:
            raise RuntimeError("missing bearer token was accepted")
        print("PASS authentication: missing token rejected")

        launcher = install_inspector(clean_cwd.name)

        initialized = inspector(launcher, url, token, "initialize")
        require(initialized.get("protocolVersion") == "2025-06-18",
                "initialize returned an unexpected protocol version")
        if args.expected_version:
            require(initialized.get("serverInfo", {}).get("version") == args.expected_version,
                    "initialize reported a server version that differs from the package")
        require(initialized.get("capabilities", {}).get("tools", {}).get("listChanged") is False,
                "initialize did not advertise the expected tools capability")
        print("PASS initialize: 2025-06-18, tools capability")

        listed = inspector(launcher, url, token, "tools/list")
        names = {tool["name"] for tool in listed["tools"]}
        require({"classify", "explain"} <= names, "tools/list omitted core tools")
        print(f"PASS tools/list: {len(names)} contracts, classify and explain present")

        observed = {"ip": "192.0.2.1", "user_agent": "GPTBot/1.0", "path": "/"}
        classified = inspector(launcher, url, token, "tools/call", "--tool-name", "classify",
                               "--tool-args-json", json.dumps(observed))
        require(classified.get("isError") is False, "classify returned an error")
        require(classified.get("structuredContent", {}).get("verdict") in
                {"allow", "challenge", "block"}, "classify omitted a structured verdict")
        print("PASS tools/call classify: structured verdict")

        explained = inspector(launcher, url, token, "tools/call", "--tool-name", "explain",
                              "--tool-args-json", json.dumps({"classification": observed}))
        require(explained.get("isError") is False, "explain returned an error")
        require(bool(explained.get("structuredContent", {}).get("factors")),
                "explain omitted contributing factors")
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
