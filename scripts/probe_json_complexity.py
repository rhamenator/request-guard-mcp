#!/usr/bin/env python3
"""Check wide JSON rejection on a running binary without exhausting memory."""

import argparse
from concurrent.futures import ThreadPoolExecutor
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
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def post(port, token, extra):
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "classify",
         "params": {"user_agent": "TEST", "path": "/", "extra": extra}},
        separators=(",", ":"),
    ).encode()
    if not 700_000 < len(payload) < 900_000:
        raise RuntimeError("probe payload size changed")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp", data=payload,
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as reply:
            return reply.status, json.load(reply)
    except urllib.error.HTTPError as error:
        return error.code, error.read(4096)


def peak_rss_kib(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    raise RuntimeError("VmHWM unavailable on this Linux runner")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    port = unused_port()
    token = secrets.token_urlsafe(48)
    env = os.environ.copy()
    for key in ("CONFIG_FILE", "MCP__REDIS__URL", "MCP__POSTGRES__URL"):
        env.pop(key, None)
    env.update(AUTH_TOKENS=token, MCP__AUTH__ENABLED="true",
               MCP__HOST="127.0.0.1", MCP__PORT=str(port), LOG_LEVEL="error")
    with tempfile.TemporaryDirectory(prefix="request-guard-complexity-") as folder:
        with (Path(folder) / "server.log").open("wb") as log:
            process = subprocess.Popen(
                [str(binary)], cwd=folder, env=env,
                stdout=log, stderr=subprocess.STDOUT,
            )
            try:
                for _ in range(50):
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/health", timeout=1
                        ) as reply:
                            if reply.status == 200:
                                break
                    except (urllib.error.URLError, OSError):
                        pass
                    if process.poll() is not None:
                        raise RuntimeError("server exited before readiness")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("server did not become ready")
                compact_status, compact = post(port, token, "0" * 800_000)
                compact_peak = peak_rss_kib(process.pid)
                wide_status, wide = post(port, token, [0] * 400_000)
                wide_peak = peak_rss_kib(process.pid)
                if compact_status != 200 or "result" not in compact:
                    raise RuntimeError("same-size compact JSON was not accepted")
                if wide_status != 413 or b"Request body exceeds limit" not in wide:
                    raise RuntimeError("wide JSON was not rejected with HTTP 413")
                if wide_peak - compact_peak > 8 * 1024:
                    raise RuntimeError("wide JSON added over 8 MiB to peak RSS")
                with ThreadPoolExecutor(max_workers=16) as pool:
                    burst = list(pool.map(lambda _: post(port, token, [0] * 400_000), range(16)))
                if any(status != 413 for status, _ in burst):
                    raise RuntimeError("concurrent wide JSON was not uniformly rejected")
                burst_peak = peak_rss_kib(process.pid)
                if burst_peak - compact_peak > 64 * 1024:
                    raise RuntimeError("16 wide JSON requests added over 64 MiB to peak RSS")
                if process.poll() is not None:
                    raise RuntimeError("server exited")
                print("PASS JSON complexity: compact accepted, wide HTTP 413, "
                      "16 concurrent wide HTTP 413, server alive; "
                      f"VmHWM compact={compact_peak} KiB, "
                      f"single-wide={wide_peak} KiB, burst={burst_peak} KiB")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


if __name__ == "__main__":
    main()
