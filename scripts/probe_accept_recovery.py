#!/usr/bin/env python3
"""Bounded Linux loopback regression for transient TCP accept exhaustion."""

import argparse
import os
import socket
import subprocess
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", help="extracted Request Guard server binary")
    args = parser.parse_args()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    environment = os.environ.copy()
    for key in ("CONFIG_FILE", "MCP__REDIS__URL", "MCP__POSTGRES__URL"):
        environment.pop(key, None)
    environment.update(
        MCP__HOST="127.0.0.1",
        MCP__PORT=str(port),
        MCP__LIMITS__MAX_CONNECTIONS="256",
        AUTH_TOKENS="synthetic-test-token-with-at-least-32-characters",
        MCP__AUTH__ENABLED="true",
        LOG_LEVEL="info",
        RUST_LOG="info",
        NO_PROXY="127.0.0.1,localhost",
        no_proxy="127.0.0.1,localhost",
    )
    sockets = []
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            ["bash", "-c", 'ulimit -n 64; exec "$1"', "bash", os.path.abspath(args.binary)],
            env=environment, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                assert process.poll() is None, "server failed to start"
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.5) as response:
                        assert response.status == 200
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("server did not start")
            for attempt in range(100):
                if process.poll() is not None:
                    raise AssertionError(f"server exited under socket pressure: {process.returncode}")
                try:
                    sockets.append(socket.create_connection(("127.0.0.1", port), timeout=0.1))
                except OSError:
                    pass
                if attempt % 10 == 0:
                    time.sleep(0.02)
            time.sleep(0.5)
            assert process.poll() is None, "server exited under socket pressure"
            for connection in sockets:
                connection.close()
            sockets.clear()

            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.5) as response:
                        assert response.status == 200
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("server did not recover after sockets closed")

            log.seek(0)
            output = log.read().decode("utf-8", errors="replace")
            assert output.count("TCP accept failed; retrying") == 1, "accept error was not observed or log flooded"
            assert output.count("TCP accept recovered") == 1, f"accept recovery was not logged once: {output[-500:]}"
            print("PASS: bounded accept warning and recovery; server stayed available")
        finally:
            for connection in sockets:
                connection.close()
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
