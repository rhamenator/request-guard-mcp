#!/usr/bin/env python3
"""Exercise packaged MCP PostgreSQL persistence through outage and recovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request


PG_DIR = Path("/tmp/request-guard-pg")
PG_LOG = Path("/tmp/request-guard-pg.log")
PG_PORT = 15432
MCP_PORT = 18780
MAX_LOG_BYTES = 64 * 1024
POSTGRES_USER = pwd.getpwnam("postgres")


def pg(*args: str) -> None:
    result = subprocess.run(list(args), user=POSTGRES_USER.pw_uid,
                            group=POSTGRES_USER.pw_gid, capture_output=True,
                            text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"test PostgreSQL command failed: {result.stderr[-300:]}")


def start_pg() -> None:
    pg("pg_ctl", "-D", str(PG_DIR), "-l", str(PG_LOG), "-o",
       f"-h 127.0.0.1 -p {PG_PORT} -k /tmp", "-w", "start")
    result = subprocess.run(["pg_isready", "-h", "127.0.0.1", "-p", str(PG_PORT),
                             "-U", "postgres"], capture_output=True, timeout=5)
    if result.returncode:
        raise RuntimeError("test PostgreSQL did not become ready")


def stop_pg() -> None:
    pg("pg_ctl", "-D", str(PG_DIR), "-m", "immediate", "-w", "stop")


def pg_running() -> bool:
    result = subprocess.run(["pg_ctl", "-D", str(PG_DIR), "status"],
                            user=POSTGRES_USER.pw_uid, group=POSTGRES_USER.pw_gid,
                            capture_output=True, timeout=5)
    return result.returncode == 0


def persisted_row(request_id: str) -> bool:
    # request_id is generated solely from a fixed prefix and hexadecimal bytes.
    query = ("SELECT COUNT(*) FROM mcp_decisions WHERE "
             f"response_payload->>'request_id' = '{request_id}'")
    result = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(PG_PORT),
                             "-U", "postgres", "-d", "postgres", "-tAc", query],
                            capture_output=True, text=True, timeout=5, check=True)
    return result.stdout.strip() == "1"


def persisted_request_payload(request_id: str) -> dict:
    # request_id is generated solely from a fixed prefix and hexadecimal bytes.
    query = ("SELECT request_payload::text FROM mcp_decisions WHERE "
             f"response_payload->>'request_id' = '{request_id}'")
    result = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(PG_PORT),
                             "-U", "postgres", "-d", "postgres", "-tAc", query],
                            capture_output=True, text=True, timeout=5, check=True)
    if not result.stdout.strip():
        raise RuntimeError("persisted decision row was not found")
    return json.loads(result.stdout)


def assert_minimized(payload: dict, sensitive: dict[str, str]) -> None:
    if payload.get("headers") != {"accept": ""}:
        raise RuntimeError("persisted header presence did not match reduced snapshot")
    if any(payload.get(name) is not None for name in
           ("ip", "body_snippet", "extra", "referer", "accept", "timestamp",
            "request_id", "tls_ja3", "tls_ja4", "tls_fingerprint_source")):
        raise RuntimeError("persisted replay request retained an excluded field")
    if any(value in json.dumps(payload) for value in sensitive.values()):
        raise RuntimeError("persisted replay request retained a synthetic secret")


def simulate_legacy_row_and_migrate(request_id: str, marker: str,
                                    sensitive: dict[str, str]) -> dict:
    legacy = {"request_id": request_id, "ip": "192.0.2.44",
              "user_agent": "Mozilla/5.0", "method": "GET", "path": f"/{marker}",
              "headers": {"ACCEPT": "application/json", "Cookie": sensitive["header"]},
              "body_snippet": sensitive["body"],
              "extra": {"token": sensitive["extra"]},
              "referer": sensitive["referer"], "accept": sensitive["accept"],
              "timestamp": sensitive["timestamp"]}
    raw = json.dumps(legacy)
    if "'" in raw:
        raise RuntimeError("synthetic legacy fixture contains a SQL quote")
    query = ("UPDATE mcp_decisions SET request_payload = "
             f"'{raw}'::jsonb WHERE response_payload->>'request_id' = '{request_id}';")
    subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(PG_PORT),
                    "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1"],
                   input=query, capture_output=True, text=True, timeout=5, check=True)
    legacy_payload = persisted_request_payload(request_id)
    if not any(value in json.dumps(legacy_payload) for value in sensitive.values()):
        raise RuntimeError("legacy fixture did not contain synthetic sensitive data")
    subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(PG_PORT),
                    "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1",
                    "-f", "/test/postgres_minimize_legacy.sql"],
                   capture_output=True, text=True, timeout=30, check=True)
    return persisted_request_payload(request_id)


def rpc(token: str, method: str, params: dict | None = None) -> dict:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    request = urllib.request.Request(f"http://127.0.0.1:{MCP_PORT}/mcp",
                                     data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json",
                                              "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=12) as response:
        return json.load(response)


def classify(token: str, request_id: str, marker: str,
             sensitive: dict[str, str] | None = None) -> dict:
    arguments = {
        "request_id": request_id, "ip": "192.0.2.44", "user_agent": "Mozilla/5.0",
        "method": "GET", "path": f"/{marker}"}
    if sensitive is not None:
        arguments.update({"headers": {"ACCEPT": "application/json",
                                      "Cookie": sensitive["header"]},
                          "body_snippet": sensitive["body"],
                          "extra": {"token": sensitive["extra"]},
                          "referer": sensitive["referer"],
                          "accept": sensitive["accept"],
                          "timestamp": sensitive["timestamp"]})
    return rpc(token, "tools/call", {"name": "classify", "arguments": arguments})


def replay(token: str, request_id: str) -> dict:
    return rpc(token, "tools/call", {"name": "replay_decision",
                                      "arguments": {"request_id": request_id,
                                                    "deterministic": True}})


def require_success(value: dict, action: str) -> dict:
    result = value.get("result", {})
    if result.get("isError") is not False:
        raise RuntimeError(f"{action} returned an MCP tool error")
    return result.get("structuredContent", {})


def require_upstream(value: dict, action: str) -> None:
    error = value.get("error", {})
    if error.get("code") != -502 or error.get("message") != "UPSTREAM_ERROR":
        raise RuntimeError(f"{action} did not return deterministic PostgreSQL upstream error")


def stop_server(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError("test server required a forced kill")


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    expected_version = sys.argv[2]
    token = secrets.token_hex(32)
    cache_key = secrets.token_hex(32)
    request_id = f"pg-ci-{secrets.token_hex(8)}"
    marker = f"pg-{secrets.token_hex(8)}"
    sensitive = {name: f"synthetic-{name}-{secrets.token_hex(8)}" for name in
                 ("header", "body", "extra", "referer", "accept", "timestamp")}
    PG_DIR.mkdir(mode=0o700)
    os.chown(PG_DIR, POSTGRES_USER.pw_uid, POSTGRES_USER.pw_gid)
    pg("initdb", "-D", str(PG_DIR), "-A", "trust", "--no-instructions")
    server = None
    with tempfile.TemporaryFile() as server_log:
        try:
            start_pg()
            env = os.environ.copy()
            env.update({"AUTH_TOKENS": token, "CACHE_SCOPE_HMAC_KEY": cache_key,
                        "MCP__HOST": "127.0.0.1", "MCP__PORT": str(MCP_PORT),
                        "MCP__POSTGRES__URL":
                            f"postgresql://postgres@127.0.0.1:{PG_PORT}/postgres",
                        "MCP__POSTGRES__MAX_CONNECTIONS": "2",
                        "MCP__POSTGRES__CONNECT_TIMEOUT_SECS": "2"})
            server = subprocess.Popen([str(binary)], env=env, stdout=server_log,
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
                                                   "clientInfo": {"name": "alpine-postgres-ci", "version": "1"}})
            if initialized["result"]["serverInfo"]["version"] != expected_version:
                raise RuntimeError("packaged server version mismatch")
            first = require_success(classify(token, request_id, marker, sensitive),
                                    "initial classify")
            if first.get("request_id") != request_id:
                raise RuntimeError("initial classification request id mismatch")
            assert_minimized(persisted_request_payload(request_id), sensitive)
            replayed = require_success(replay(token, request_id), "initial replay")
            if replayed.get("matches_original") is not True:
                raise RuntimeError("initial replay did not match")
            migrated = simulate_legacy_row_and_migrate(request_id, marker, sensitive)
            assert_minimized(migrated, sensitive)
            migrated_replay = require_success(replay(token, request_id), "migrated replay")
            if migrated_replay.get("matches_original") is not True:
                raise RuntimeError("migrated replay did not match")
            stop_pg()
            require_upstream(classify(token, f"{request_id}-outage", marker), "outage classify")
            require_upstream(replay(token, request_id), "outage replay")
            ping = rpc(token, "ping")
            if "error" in ping or "result" not in ping:
                raise RuntimeError("core MCP ping failed during PostgreSQL outage")
            start_pg()
            if not persisted_row(request_id):
                raise RuntimeError("persisted decision was missing after PostgreSQL restart")
            restored = require_success(classify(token, f"{request_id}-restored", marker),
                                       "restored classify")
            if restored.get("request_id") != f"{request_id}-restored":
                raise RuntimeError("restored classification request id mismatch")
            replayed = require_success(replay(token, request_id), "restored replay")
            if replayed.get("matches_original") is not True:
                raise RuntimeError("restored replay did not match")
        finally:
            pending_failure = sys.exc_info()[0] is not None
            try:
                stop_server(server)
            finally:
                try:
                    if pg_running():
                        stop_pg()
                except (RuntimeError, subprocess.TimeoutExpired):
                    if not pending_failure:
                        raise
            if not pending_failure:
                server_log.seek(0)
                captured = server_log.read(MAX_LOG_BYTES + 1)
                with PG_LOG.open("rb") as pg_log:
                    pg_captured = pg_log.read(MAX_LOG_BYTES + 1)
                if (not captured or len(captured) > MAX_LOG_BYTES
                        or len(pg_captured) > MAX_LOG_BYTES):
                    raise RuntimeError("Alpine PostgreSQL logs were empty or exceeded 64 KiB")
                for secret in (token, cache_key, request_id, marker):
                    if secret.encode() in captured:
                        raise RuntimeError("Alpine MCP server log disclosed a synthetic secret")
    print("PASS Alpine PostgreSQL: classify/replay, outage -502, ping, recovery, private logs")


if __name__ == "__main__":
    main()
