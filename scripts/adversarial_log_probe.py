#!/usr/bin/env python3
"""Check bounded loopback MCP calls do not write synthetic secrets to server logs."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

from adversarial_probe import post, rpc
from ci_adversarial_smoke import unused_loopback_port, wait_for_health


def check(name, passed, detail):
    print(json.dumps({"case": name, "pass": bool(passed), "detail": detail}), flush=True)
    return bool(passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    port = unused_loopback_port()
    token = secrets.token_urlsafe(48)
    marker = "synthetic-private-" + secrets.token_hex(12)
    environment = os.environ.copy()
    environment.pop("CONFIG_FILE", None)
    environment.pop("RUST_LOG", None)
    environment.pop("MCP__REDIS__URL", None)
    environment.pop("MCP__POSTGRES__URL", None)
    environment.pop("MCP__TELEMETRY__OTLP_ENDPOINT", None)
    environment.update({
        "AUTH_TOKENS": token,
        "MCP__AUTH__ENABLED": "true",
        "MCP__HOST": "127.0.0.1",
        "MCP__PORT": str(port),
        "LOG_LEVEL": "debug",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    })
    results = []
    with tempfile.TemporaryDirectory() as working_directory:
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(
                [str(binary)], cwd=working_directory, env=environment,
                stdout=log, stderr=subprocess.STDOUT,
            )
            try:
                wait_for_health(process, port)
                base = f"http://127.0.0.1:{port}"
                wrong_status, _ = post(base, token + "wrong", rpc("ping"))
                results.append(check("log_probe_rejected_auth", wrong_status == 403, wrong_status))
                missing_statuses = [post(base, token, rpc("ping"), authorize=False)[0] for _ in range(64)]
                wrong_statuses = [post(base, token + "wrong", rpc("ping"))[0] for _ in range(64)]
                results.append(check(
                    "bounded_auth_flood_rejected",
                    all(status == 401 for status in missing_statuses)
                    and all(status == 403 for status in wrong_statuses),
                    {"missing": len(missing_statuses), "wrong": len(wrong_statuses)},
                ))
                status, body = post(base, token, rpc("tools/call", {
                    "name": "classify",
                    "arguments": {
                        "ip": "198.51.100.25", "user_agent": marker,
                        "method": "GET", "path": "/private/" + marker,
                    },
                }))
                value = json.loads(body)
                results.append(check(
                    "log_probe_classify", status == 200
                    and value.get("result", {}).get("isError") is False,
                    status,
                ))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            log.seek(0)
            output = log.read(1024 * 1024 + 1)
            full_capture = len(output) <= 1024 * 1024
            observable = b"request-guard-mcp starting" in output
            no_auth_logs = (b"request missing authorization header" not in output
                            and b"invalid bearer token presented" not in output)
            clean = token.encode() not in output and marker.encode() not in output
            results.append(check("synthetic_secrets_absent_from_logs", full_capture and observable and clean and no_auth_logs, {
                "bounded": full_capture, "observed_start": observable,
                "no_per_request_auth_logs": no_auth_logs,
                "secret_or_marker_found": not clean,
            }))
    print(json.dumps({"passed": sum(results), "total": len(results)}))
    raise SystemExit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
