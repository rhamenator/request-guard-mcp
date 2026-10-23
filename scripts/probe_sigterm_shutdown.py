#!/usr/bin/env python3
"""Exercise bounded SIGTERM drain of a partially received authenticated MCP request."""

from __future__ import annotations

import argparse
import os
import pathlib
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_health(process: subprocess.Popen[bytes], port: int) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(f"server exited before readiness ({process.returncode})")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server did not become ready")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    port = free_port()
    token = secrets.token_urlsafe(32)
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "HOME", "TMPDIR", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
    env.update({
        "MCP__HOST": "127.0.0.1",
        "MCP__PORT": str(port),
        "MCP__AUTH__ENABLED": "true",
        "AUTH_TOKENS": token,
        "MCP__LIMITS__HTTP_BODY_TIMEOUT_SECS": "2",
        "MCP__LIMITS__PER_TOOL_TIMEOUT_SECS": "1",
        "MCP__LIMITS__CLASSIFY_TIMEOUT_SECS": "1",
    })
    body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
    headers = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
               f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\n\r\n").encode()

    with tempfile.TemporaryDirectory(prefix="request-guard-sigterm-") as cwd:
        process = subprocess.Popen([str(binary)], cwd=cwd, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for_health(process, port)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.settimeout(8)
                client.sendall(headers + body[:-1])
                time.sleep(0.15)
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                time.sleep(0.15)
                client.sendall(body[-1:])
                response = bytearray()
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
                if not bytes(response).startswith(b"HTTP/1.1 200"):
                    raise RuntimeError(f"active request did not complete: {bytes(response[:80])!r}")
            code = process.wait(timeout=8)
            elapsed = time.monotonic() - started
            if code != 0:
                raise RuntimeError(f"SIGTERM exit was {code}, expected 0")
            if elapsed > 8:
                raise RuntimeError(f"shutdown exceeded deadline: {elapsed:.3f}s")
            print(f"PASS SIGTERM: active MCP response completed; exit 0 in {elapsed:.3f}s")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    # An idle HTTP keep-alive peer must not consume the entire active-request
    # drain window just because it leaves the socket open.
    port = free_port()
    env["MCP__PORT"] = str(port)
    with tempfile.TemporaryDirectory(prefix="request-guard-sigterm-idle-") as cwd:
        process = subprocess.Popen([str(binary)], cwd=cwd, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for_health(process, port)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.settimeout(3)
                client.sendall(f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
                if not client.recv(4096).startswith(b"HTTP/1.1 200"):
                    raise RuntimeError("idle control request failed")
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=3)
                if code != 0 or time.monotonic() - started > 3:
                    raise RuntimeError("idle keep-alive delayed graceful shutdown")
                print("PASS SIGTERM: idle HTTP keep-alive closed promptly; exit 0")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    # A socket that never completes even its protocol preface has no response
    # to drain and must not hold process termination for the full tool window.
    port = free_port()
    env["MCP__PORT"] = str(port)
    with tempfile.TemporaryDirectory(prefix="request-guard-sigterm-silent-") as cwd:
        process = subprocess.Popen([str(binary)], cwd=cwd, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for_health(process, port)
            with socket.create_connection(("127.0.0.1", port), timeout=3):
                time.sleep(0.15)
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=3)
                if code != 0 or time.monotonic() - started > 3:
                    raise RuntimeError("silent preface delayed graceful shutdown")
                print("PASS SIGTERM: silent preface closed promptly; exit 0")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    # A second signal is the operator's forced-exit escape hatch if a peer
    # still holds an active body read during the drain window.
    port = free_port()
    env["MCP__PORT"] = str(port)
    with tempfile.TemporaryDirectory(prefix="request-guard-sigterm-force-") as cwd:
        process = subprocess.Popen([str(binary)], cwd=cwd, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for_health(process, port)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall((f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                                f"Authorization: Bearer {token}\r\n"
                                "Content-Type: application/json\r\n"
                                f"Content-Length: {len(body)}\r\n\r\n").encode() + body[:-1])
                time.sleep(0.15)
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                time.sleep(0.15)
                if process.poll() is not None:
                    raise RuntimeError("first signal did not leave an active drain window")
                process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=2)
                if code != 1 or time.monotonic() - started > 2:
                    raise RuntimeError(f"second signal did not force exit promptly ({code})")
                print("PASS SIGTERM: second signal forces exit during active drain")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
