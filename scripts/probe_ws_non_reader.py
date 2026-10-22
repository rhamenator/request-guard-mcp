#!/usr/bin/env python3
"""Bounded loopback regression for non-reading WebSocket connection permits."""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def unused_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def upgrade(port, token):
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    sock.settimeout(1)
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: mcp\r\nAuthorization: Bearer {token}\r\n\r\n"
    )
    sock.sendall(request.encode())
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 8192:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    status = int(data.split(b" ", 2)[1])
    return sock, status


def send_tools_list(sock, request_id):
    payload = json.dumps({"jsonrpc": "2.0", "id": request_id,
                          "method": "tools/list"}).encode()
    mask = os.urandom(4)
    sock.sendall(bytes((0x81, 0x80 | len(payload))) + mask +
                 bytes(byte ^ mask[index % 4]
                       for index, byte in enumerate(payload)))


def health(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
            return response.status
    except (urllib.error.URLError, OSError):
        return None


def wait_for_upgrade(port, token, seconds):
    deadline = time.monotonic() + seconds
    status = None
    while time.monotonic() < deadline:
        sock, status = upgrade(port, token)
        sock.close()
        if status == 101:
            return status
        time.sleep(0.25)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    port = unused_port()
    token = secrets.token_urlsafe(48)
    env = os.environ.copy()
    env.pop("CONFIG_FILE", None)
    env.pop("MCP__REDIS__URL", None)
    env.update(AUTH_TOKENS=token, MCP__AUTH__ENABLED="true",
               MCP__HOST="127.0.0.1", MCP__PORT=str(port),
               MCP__LIMITS__MAX_CONNECTIONS="2",
               MCP__LIMITS__WEBSOCKET_IDLE_TIMEOUT_SECS="2",
               LOG_LEVEL="warn")
    sockets = []
    with tempfile.TemporaryDirectory() as working_dir:
        log_path = Path(working_dir) / "server.log"
        server_log = log_path.open("wb")
        # Listener-mode tracing writes to stdout; stdio transport differs.
        process = subprocess.Popen([str(binary)], cwd=working_dir, env=env,
                                   stdout=server_log, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):
                if health(port) == 200:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("server failed to start")

            # Idle control: the normal read-side deadline must release slots.
            for _ in range(2):
                sock, status = upgrade(port, token)
                assert status == 101, status
                sockets.append(sock)
            control_status = wait_for_upgrade(port, token, 6)
            assert control_status == 101, control_status
            for sock in sockets:
                sock.close()
            sockets.clear()

            # Fill both server write paths without reading their responses.
            for _ in range(2):
                sock, status = upgrade(port, token)
                assert status == 101, status
                sockets.append(sock)
            counts = []
            for sock in sockets:
                sent = 0
                sock.settimeout(0.2)
                for request_id in range(1000):
                    try:
                        send_tools_list(sock, request_id)
                        sent += 1
                    except (socket.timeout, OSError):
                        break
                counts.append(sent)
            recovered_status = wait_for_upgrade(port, token, 12)
            assert min(counts) >= 100, counts
            assert process.poll() is None
            assert health(port) == 200
            assert recovered_status == 101, recovered_status
            # Listener-mode tracing is captured from stdout. Require evidence
            # that the outgoing send deadline, rather than another close path,
            # released at least one of the occupied permits.
            send_deadline_logged = "WebSocket send deadline exceeded" in log_path.read_text()
            assert send_deadline_logged
            print(json.dumps({"case": "non_reading_websocket_recovery",
                              "passed": True, "sent": counts,
                              "idle_control": control_status,
                              "recovered_upgrade": recovered_status,
                              "send_deadline_logged": send_deadline_logged}), flush=True)
        finally:
            for sock in sockets:
                sock.close()
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            server_log.close()


if __name__ == "__main__":
    main()
