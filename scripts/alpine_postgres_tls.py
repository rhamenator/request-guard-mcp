#!/usr/bin/env python3
"""Prove packaged musl PostgreSQL TLS trust and rejection paths."""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

from alpine_postgres_recovery import (
    MCP_PORT, PG_DIR, PG_LOG, PG_PORT, POSTGRES_USER, classify, pg,
    replay, require_success, rpc, start_pg, stop_pg, stop_server,
)


CERT_DIR = Path("/tmp/request-guard-pg-certs")
MAX_LOG_BYTES = 64 * 1024


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=30)


def create_certificates() -> tuple[Path, Path]:
    CERT_DIR.mkdir(mode=0o700)
    ca = CERT_DIR / "trusted-ca.crt"
    ca_key = CERT_DIR / "trusted-ca.key"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
            "-subj", "/CN=Request Guard CI CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(ca_key), "-out", str(ca))
    openssl("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
            "-subj", "/CN=Untrusted Request Guard CI CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(CERT_DIR / "untrusted.key"),
            "-out", str(CERT_DIR / "untrusted-ca.crt"))
    key = CERT_DIR / "server.key"
    csr = CERT_DIR / "server.csr"
    openssl("req", "-newkey", "rsa:2048", "-noenc", "-subj", "/CN=pgci.test",
            "-keyout", str(key), "-out", str(csr))
    extensions = CERT_DIR / "server.ext"
    extensions.write_text("subjectAltName=DNS:pgci.test\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
            "-extfile", str(extensions), "-out", str(CERT_DIR / "server.crt"))
    for filename in ("server.key", "server.crt"):
        destination = PG_DIR / filename
        shutil.copyfile(CERT_DIR / filename, destination)
        os.chown(destination, POSTGRES_USER.pw_uid, POSTGRES_USER.pw_gid)
        destination.chmod(0o600 if filename.endswith(".key") else 0o644)
    with (PG_DIR / "postgresql.conf").open("a") as config:
        config.write("\nssl = on\nssl_cert_file = 'server.crt'\nssl_key_file = 'server.key'\n")
    return ca, CERT_DIR / "untrusted-ca.crt"


def run_case(binary: Path, expected_version: str, token: str, cache_key: str,
             name: str, *, host: str, root_cert: Path | None, should_start: bool) -> None:
    query = "sslmode=verify-full"
    if root_cert is not None:
        query += f"&sslrootcert={root_cert}"
    env = os.environ.copy()
    env.update({"AUTH_TOKENS": token, "CACHE_SCOPE_HMAC_KEY": cache_key,
                "MCP__HOST": "127.0.0.1", "MCP__PORT": str(MCP_PORT),
                "MCP__POSTGRES__URL":
                    f"postgresql://postgres@{host}:{PG_PORT}/postgres?{query}",
                "MCP__POSTGRES__MAX_CONNECTIONS": "2",
                "MCP__POSTGRES__CONNECT_TIMEOUT_SECS": "2"})
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen([str(binary)], env=env, stdout=log,
                                   stderr=subprocess.STDOUT)
        try:
            if should_start:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError(f"{name}: packaged server exited before readiness")
                    try:
                        with urllib.request.urlopen(
                                f"http://127.0.0.1:{MCP_PORT}/health", timeout=1):
                            break
                    except (OSError, TimeoutError):
                        time.sleep(0.1)
                else:
                    raise RuntimeError(f"{name}: packaged server did not become ready")
                initialized = rpc(token, "initialize", {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "alpine-postgres-tls-ci", "version": "1"}})
                if initialized["result"]["serverInfo"]["version"] != expected_version:
                    raise RuntimeError(f"{name}: packaged server version mismatch")
                request_id = f"pg-tls-{secrets.token_hex(8)}"
                result = require_success(classify(token, request_id, "pg-tls"), name)
                if result.get("request_id") != request_id:
                    raise RuntimeError(f"{name}: classify request ID mismatch")
                if require_success(replay(token, request_id), name).get("matches_original") is not True:
                    raise RuntimeError(f"{name}: replay failed")
            else:
                try:
                    exit_code = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    raise RuntimeError(f"{name}: untrusted PostgreSQL TLS started") from None
                if exit_code == 0:
                    raise RuntimeError(f"{name}: untrusted PostgreSQL TLS exited successfully")
        finally:
            pending_failure = sys.exc_info()[0] is not None
            stop_server(process)
            if not pending_failure:
                log.seek(0)
                captured = log.read(MAX_LOG_BYTES + 1)
                if not captured or len(captured) > MAX_LOG_BYTES:
                    raise RuntimeError(f"{name}: server log empty or exceeded 64 KiB")
                for secret in (token, cache_key):
                    if secret.encode() in captured:
                        raise RuntimeError(f"{name}: synthetic secret appeared in server log")
                if not should_start and b"certificate" not in captured.lower():
                    raise RuntimeError(f"{name}: failure was not attributable to TLS certificate verification")


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    expected_version = sys.argv[2]
    token = secrets.token_hex(32)
    cache_key = secrets.token_hex(32)
    PG_DIR.mkdir(mode=0o700)
    os.chown(PG_DIR, POSTGRES_USER.pw_uid, POSTGRES_USER.pw_gid)
    pg("initdb", "-D", str(PG_DIR), "-A", "trust", "--no-instructions")
    trusted_ca, untrusted_ca = create_certificates()
    try:
        start_pg()
        run_case(binary, expected_version, token, cache_key, "explicit trusted CA",
                 host="pgci.test", root_cert=trusted_ca, should_start=True)
        run_case(binary, expected_version, token, cache_key, "untrusted CA",
                 host="pgci.test", root_cert=untrusted_ca, should_start=False)
        run_case(binary, expected_version, token, cache_key, "hostname mismatch",
                 host="127.0.0.1", root_cert=trusted_ca, should_start=False)
        run_case(binary, expected_version, token, cache_key, "OS store before CA installation",
                 host="pgci.test", root_cert=None, should_start=False)
        destination = Path("/usr/local/share/ca-certificates/request-guard-ci.crt")
        shutil.copyfile(trusted_ca, destination)
        subprocess.run(["update-ca-certificates"], check=True, capture_output=True, timeout=30)
        run_case(binary, expected_version, token, cache_key, "OS store trusted CA",
                 host="pgci.test", root_cert=None, should_start=True)
    finally:
        pending_failure = sys.exc_info()[0] is not None
        if subprocess.run(["pg_ctl", "-D", str(PG_DIR), "status"],
                          user=POSTGRES_USER.pw_uid, group=POSTGRES_USER.pw_gid,
                          capture_output=True, timeout=5).returncode == 0:
            stop_pg()
        if not pending_failure:
            pg_captured = PG_LOG.read_bytes()[:MAX_LOG_BYTES + 1]
            if not pg_captured or len(pg_captured) > MAX_LOG_BYTES:
                raise RuntimeError("PostgreSQL log empty or exceeded 64 KiB")
            for secret in (token, cache_key):
                if secret.encode() in pg_captured:
                    raise RuntimeError("synthetic secret appeared in PostgreSQL log")
    print("PASS Alpine PostgreSQL TLS: explicit CA, untrusted CA, hostname, OS store, private logs")


if __name__ == "__main__":
    main()
