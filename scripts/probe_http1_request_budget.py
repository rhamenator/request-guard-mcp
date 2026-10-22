#!/usr/bin/env python3
"""Exercise the running binary's bounded HTTP/1 keep-alive request budget."""

import argparse
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


REQUESTS = 128


def unused_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def health(port: int) -> int | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as reply:
            return reply.status
    except (urllib.error.URLError, OSError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    port = unused_port()
    env = os.environ.copy()
    for key in ("CONFIG_FILE", "MCP__REDIS__URL", "MCP__POSTGRES__URL"):
        env.pop(key, None)
    env.update(AUTH_TOKENS=secrets.token_urlsafe(48), MCP__AUTH__ENABLED="true",
               MCP__HOST="127.0.0.1", MCP__PORT=str(port),
               MCP__LIMITS__MAX_CONNECTIONS="1",
               MCP__LIMITS__HTTP_HEADER_TIMEOUT_SECS="30", LOG_LEVEL="warn")
    with tempfile.TemporaryDirectory() as working_dir:
        with (Path(working_dir) / "server.log").open("wb") as server_log:
            process = subprocess.Popen([str(binary)], cwd=working_dir, env=env,
                                       stdout=server_log, stderr=subprocess.STDOUT)
            try:
                for _ in range(40):
                    if health(port) == 200:
                        break
                    if process.poll() is not None:
                        raise RuntimeError("server exited before readiness")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("server did not become ready")
                # The readiness client requested close; allow its permit to drop.
                time.sleep(0.2)
                request = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
                with socket.create_connection(("127.0.0.1", port), timeout=2) as busy:
                    busy.settimeout(5)
                    busy.sendall(request * REQUESTS)
                    chunks = []
                    while True:
                        chunk = busy.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if sum(map(len, chunks)) > 256 * 1024:
                            raise RuntimeError("HTTP/1 budget response exceeded 256 KiB")
                responses = b"".join(chunks)
                parts = responses.split(b"HTTP/1.1 200")
                if len(parts) - 1 != REQUESTS or responses.count(b"HTTP/1.1 ") != REQUESTS:
                    raise RuntimeError("HTTP/1 budget did not serve exactly 128 responses")
                final_headers = parts[-1].split(b"\r\n\r\n", 1)[0].lower()
                if b"connection: close" not in final_headers:
                    raise RuntimeError("final HTTP/1 response lacked Connection: close")
                recovered = None
                for _ in range(10):
                    recovered = health(port)
                    if recovered == 200:
                        break
                    time.sleep(0.1)
                if process.poll() is not None or recovered != 200:
                    raise RuntimeError("new client did not recover after HTTP/1 budget close")
                print("PASS HTTP/1 request budget: 128 responses, close, recovery")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


if __name__ == "__main__":
    main()
