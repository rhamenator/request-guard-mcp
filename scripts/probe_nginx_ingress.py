#!/usr/bin/env python3
"""Bounded loopback nginx ingress check against a packaged server binary.

Requires nginx on PATH. Uses temporary ports, credentials, and configuration;
it does not modify the host nginx service or test production TLS settings.
"""

import argparse
import base64
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
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def status(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as reply:
            return reply.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, OSError):
        return None


def stop(process):
    if process is None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--nginx", default="nginx")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    backend_port, proxy_port = unused_port(), unused_port()
    token = secrets.token_urlsafe(48)
    env = os.environ.copy()
    for key in ("CONFIG_FILE", "MCP__REDIS__URL", "MCP__POSTGRES__URL"):
        env.pop(key, None)
    env.update(
        AUTH_TOKENS=token,
        MCP__AUTH__ENABLED="true",
        MCP__HOST="127.0.0.1",
        MCP__PORT=str(backend_port),
        MCP__LIMITS__MAX_CONNECTIONS="2",
        LOG_LEVEL="error",
    )
    with tempfile.TemporaryDirectory(prefix="request-guard-nginx-") as folder:
        root = Path(folder)
        for name in ("client", "proxy", "fastcgi", "uwsgi", "scgi"):
            (root / name).mkdir()
        config = f"""pid {root}/nginx.pid;
error_log {root}/nginx-error.log warn;
events {{ worker_connections 128; }}
http {{
  access_log off;
  client_body_temp_path {root}/client;
  proxy_temp_path {root}/proxy;
  fastcgi_temp_path {root}/fastcgi;
  uwsgi_temp_path {root}/uwsgi;
  scgi_temp_path {root}/scgi;
  limit_req_zone $binary_remote_addr zone=rg_rate:1m rate=2r/s;
  limit_conn_zone $binary_remote_addr zone=rg_conn:1m;
  map $http_upgrade $rg_connection {{ default upgrade; "" close; }}
  server {{ listen 127.0.0.1:{proxy_port};
    client_header_timeout 1s;
    client_body_timeout 2s;
    send_timeout 2s;
    location / {{
      limit_req zone=rg_rate burst=2 nodelay;
      limit_conn rg_conn 1;
      limit_req_status 429;
      limit_conn_status 430;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $rg_connection;
      proxy_connect_timeout 1s;
      proxy_read_timeout 3s;
      proxy_pass http://127.0.0.1:{backend_port};
    }}
  }}
}}"""
        config_path = root / "nginx.conf"
        config_path.write_text(config)
        check = subprocess.run(
            [args.nginx, "-t", "-p", f"{root}/", "-e", str(root / "nginx-error.log"),
             "-c", str(config_path)],
            capture_output=True, text=True,
        )
        if check.returncode:
            raise RuntimeError(f"nginx config test failed: {check.stderr[-2000:]}")
        proxy = None
        with (root / "server.log").open("wb") as server_log:
            server = subprocess.Popen(
                [str(binary)], cwd=root, env=env,
                stdout=server_log, stderr=subprocess.STDOUT,
            )
            try:
                for _ in range(50):
                    if status(backend_port) == 200:
                        break
                    if server.poll() is not None:
                        raise RuntimeError("server exited before readiness")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("server did not become ready")
                proxy = subprocess.Popen(
                    [args.nginx, "-p", f"{root}/", "-e", str(root / "nginx-error.log"),
                     "-c", str(config_path),
                     "-g", "daemon off;"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                for _ in range(50):
                    if status(proxy_port) == 200:
                        break
                    if proxy.poll() is not None:
                        raise RuntimeError("nginx exited before readiness")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("nginx did not become ready")
                # Each wave uses fresh HTTP clients. Excess connections must be
                # rejected at the proxy while both processes remain healthy.
                for wave in range(3):
                    time.sleep(1.2)
                    outcomes = [status(proxy_port) for _ in range(12)]
                    if 200 not in outcomes or 429 not in outcomes:
                        raise RuntimeError(f"rate wave {wave + 1}: {outcomes}")
                time.sleep(1.2)
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as held:
                    held.sendall(
                        b"POST /mcp HTTP/1.1\r\nHost: local\r\n"
                        b"Content-Length: 100000\r\nContent-Type: application/json\r\n\r\n"
                    )
                    time.sleep(0.2)
                    if status(proxy_port) != 430:
                        raise RuntimeError("concurrent request was not limited at proxy")
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as partial:
                    partial.sendall(b"GET /health HTTP/1.1\r\nHost: local\r\nX-Incomplete: ")
                    partial.settimeout(3)
                    time.sleep(1.5)
                    response = partial.recv(1024)
                    if response and b"408" not in response:
                        raise RuntimeError("partial header was not dropped or timed out")
                time.sleep(1.2)
                if status(proxy_port) != 200:
                    raise RuntimeError("healthy request did not recover")
                time.sleep(1.2)
                payload = (
                    b'{"jsonrpc":"2.0","id":1,"method":"initialize",'
                    b'"params":{"protocolVersion":"2025-06-18","capabilities":{},'
                    b'"clientInfo":{"name":"proxy-probe","version":"0.1"}}}'
                )
                request = urllib.request.Request(
                    f"http://127.0.0.1:{proxy_port}/mcp", data=payload,
                    headers={"Authorization": f"Bearer {token}",
                             "Content-Type": "application/json",
                             "Accept": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=3) as reply:
                    if reply.status != 200 or b"protocolVersion" not in reply.read(65536):
                        raise RuntimeError("authenticated MCP initialization failed")
                time.sleep(1.2)
                key = base64.b64encode(secrets.token_bytes(16)).decode()
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as ws:
                    ws.settimeout(3)
                    ws.sendall((
                        f"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:{proxy_port}\r\n"
                        f"Authorization: Bearer {token}\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n"
                    ).encode())
                    if b"101 Switching Protocols" not in ws.recv(4096):
                        raise RuntimeError("authenticated WebSocket upgrade failed")
                if server.poll() is not None or proxy.poll() is not None:
                    raise RuntimeError("server or proxy exited")
                print("PASS ingress: three rate waves (429) and concurrent limit (430), partial-header deadline, "
                      "health recovery, MCP initialize, WebSocket upgrade")
            except Exception:
                error_log = root / "nginx-error.log"
                if error_log.exists():
                    print("nginx diagnostic tail:", error_log.read_text(errors="replace")[-2000:])
                raise
            finally:
                try:
                    stop(proxy)
                finally:
                    stop(server)


if __name__ == "__main__":
    main()
