#!/usr/bin/env python3
"""Run bounded HTTP and WebSocket adversarial probes against a built server."""

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
LAB_MAX_REQUEST_BYTES = 4096


def unused_loopback_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_health(process, port):
    deadline = time.monotonic() + 20
    url = f"http://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited before health check: {process.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.25)
    raise TimeoutError("server did not become healthy within 20 seconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    port = unused_loopback_port()
    token = secrets.token_urlsafe(48)
    environment = os.environ.copy()
    environment.update(
        {
            "AUTH_TOKENS": token,
            "MCP__AUTH__ENABLED": "true",
            "MCP__HOST": "127.0.0.1",
            "MCP__PORT": str(port),
            "MCP__LIMITS__MAX_REQUEST_BYTES": str(LAB_MAX_REQUEST_BYTES),
            "MCP__LIMITS__HTTP_HEADER_TIMEOUT_SECS": "1",
            "MCP__LIMITS__HTTP_BODY_TIMEOUT_SECS": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        }
    )
    digest = hashlib.sha256()
    with binary.open("rb") as executable:
        for block in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(block)
    print(f"binary_sha256={digest.hexdigest()}", flush=True)
    with tempfile.TemporaryDirectory() as working_directory:
        process = subprocess.Popen(
            [str(binary)],
            cwd=working_directory,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait_for_health(process, port)
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/adversarial_probe.py"),
                    "--url",
                    f"http://127.0.0.1:{port}",
                    "--max-request-bytes",
                    str(LAB_MAX_REQUEST_BYTES),
                ],
                input=token + "\n",
                text=True,
                env=environment,
                check=True,
                timeout=90,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/adversarial_ws_probe.py"),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                input=token + "\n",
                text=True,
                env=environment,
                check=True,
                timeout=90,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/adversarial_classifier_probe.py"),
                    "--url",
                    f"http://127.0.0.1:{port}",
                ],
                input=token + "\n",
                text=True,
                env=environment,
                check=True,
                timeout=90,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/adversarial_slow_client_probe.py"),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--max-request-bytes",
                    str(LAB_MAX_REQUEST_BYTES),
                ],
                input=token + "\n",
                text=True,
                env=environment,
                check=True,
                timeout=30,
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
