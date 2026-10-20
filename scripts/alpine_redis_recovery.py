#!/usr/bin/env python3
"""Exercise packaged MCP Redis lookup through healthy, outage, and recovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


REDIS_PORT = 16379
MCP_PORT = 18779
MAX_LOG_BYTES = 64 * 1024


def redis_cli(*args: str) -> str:
    result = subprocess.run(["redis-cli", "-h", "127.0.0.1", "-p", str(REDIS_PORT), *args],
                            capture_output=True, text=True, timeout=5, check=True)
    return result.stdout.strip()


def start_redis() -> subprocess.Popen:
    process = subprocess.Popen(["redis-server", "--bind", "127.0.0.1", "--port",
                                str(REDIS_PORT), "--save", "", "--appendonly", "no",
                                "--loglevel", "warning"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    for _ in range(50):
        if process.poll() is not None:
            raise RuntimeError("test Redis exited before readiness")
        try:
            if redis_cli("PING") == "PONG":
                return process
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.1)
    raise RuntimeError("test Redis did not become ready")


def stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError("test process required a forced kill")


def rpc(token: str, method: str, params: dict) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{MCP_PORT}/mcp", data=payload,
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json",
                                              "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def lookup(token: str, indicator: str) -> dict:
    return rpc(token, "tools/call", {"name": "threat_lookup",
                                      "arguments": {"indicator": indicator}})


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    expected_version = sys.argv[2]
    token = secrets.token_hex(32)
    indicator = f"ci-{secrets.token_hex(8)}.example"
    record = json.dumps({"threat_type": "ci_probe", "severity": "high",
                         "source": "alpine_ci"}, separators=(",", ":"))
    redis = None
    server = None
    with tempfile.TemporaryFile() as log_file:
        try:
            redis = start_redis()
            redis_cli("HSET", "ci_probe:threats:domain", indicator, record)
            env = os.environ.copy()
            env.update({"AUTH_TOKENS": token, "MCP__HOST": "127.0.0.1",
                        "MCP__PORT": str(MCP_PORT),
                        "MCP__REDIS__URL": f"redis://127.0.0.1:{REDIS_PORT}",
                        "MCP__REDIS__KEY_PREFIX": "ci_probe"})
            server = subprocess.Popen([str(binary)], env=env, stdout=log_file,
                                      stderr=subprocess.STDOUT)
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("packaged musl server exited before readiness")
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{MCP_PORT}/health", timeout=1):
                        break
                except (OSError, TimeoutError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("packaged musl server did not become ready")
            initialized = rpc(token, "initialize", {"protocolVersion": "2025-06-18",
                                                   "capabilities": {},
                                                   "clientInfo": {"name": "alpine-redis-ci", "version": "1"}})
            if initialized["result"]["serverInfo"]["version"] != expected_version:
                raise RuntimeError("packaged server version mismatch")
            healthy = lookup(token, indicator)
            healthy_record = healthy.get("result", {}).get("structuredContent", {})
            if healthy_record.get("found") is not True or healthy_record.get("source") != "alpine_ci":
                raise RuntimeError("seeded Redis threat was not found")
            stop(redis)
            redis = None
            unavailable = lookup(token, indicator)
            error = unavailable.get("error", {})
            if error.get("code") != -502 or error.get("message") != "UPSTREAM_ERROR":
                raise RuntimeError("Redis outage did not return deterministic upstream error")
            core = rpc(token, "tools/call", {"name": "classify", "arguments": {
                "ip": "192.0.2.1", "user_agent": "Mozilla/5.0", "path": "/health-check"}})
            if core.get("result", {}).get("isError") is not False:
                raise RuntimeError("core classify failed during Redis outage")
            redis = start_redis()
            redis_cli("HSET", "ci_probe:threats:domain", indicator, record)
            recovered = lookup(token, indicator)
            recovered_record = recovered.get("result", {}).get("structuredContent", {})
            if recovered_record.get("found") is not True or recovered_record.get("source") != "alpine_ci":
                raise RuntimeError("Redis threat lookup did not recover")
        finally:
            pending_failure = sys.exc_info()[0] is not None
            try:
                stop(server)
            finally:
                stop(redis)
            if not pending_failure:
                log_file.seek(0)
                captured = log_file.read(MAX_LOG_BYTES + 1)
                if not captured or len(captured) > MAX_LOG_BYTES:
                    raise RuntimeError("Alpine Redis test log was empty or exceeded 64 KiB")
                if token.encode() in captured or indicator.encode() in captured:
                    raise RuntimeError("Alpine Redis test log disclosed a synthetic token or indicator")
    print("PASS Alpine Redis: seeded lookup, outage -502, core recovery, lookup recovery, private logs")


if __name__ == "__main__":
    main()
