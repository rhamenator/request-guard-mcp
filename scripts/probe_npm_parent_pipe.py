#!/usr/bin/env python3
"""Check that a packaged HTTP child exits when its npm launcher is SIGKILLed."""

import argparse
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def healthy(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.3) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def process_identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return fields[19], fields[0]
    except (FileNotFoundError, ProcessLookupError):
        # procfs may discard a short-lived child between lookup and read.
        return None


def listener_closed(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    launcher_source = Path(__file__).resolve().parents[1] / "npm/bin/request-guard-mcp.js"
    with tempfile.TemporaryDirectory(prefix="rg-npm-parent-pipe-") as cwd:
        root = Path(cwd)
        launcher = root / "bin/request-guard-mcp.js"
        vendor = root / "vendor/linux-x64/request-guard-mcp"
        launcher.parent.mkdir()
        vendor.parent.mkdir(parents=True)
        shutil.copyfile(launcher_source, launcher)
        shutil.copyfile(binary, vendor)
        launcher.chmod(0o755)
        vendor.chmod(0o755)
        port = free_port()
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"PATH", "TMPDIR"}}
        env.update({"HOME": cwd, "MCP__HOST": "127.0.0.1", "MCP__PORT": str(port),
                    "MCP__AUTH__ENABLED": "true",
                    "AUTH_TOKENS": "synthetic-parent-pipe-token-abcdefghijklmnopqrstuvwxyz123456",
                    "LOG_LEVEL": "error"})
        wrapper = subprocess.Popen(["node", str(launcher)], cwd=cwd, env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        child_pid = None
        child_start = None
        try:
            for _ in range(100):
                if healthy(port):
                    break
                if wrapper.poll() is not None:
                    raise AssertionError("npm wrapper exited before HTTP health was available")
                time.sleep(0.05)
            else:
                raise AssertionError("npm wrapper did not start HTTP listener")
            children = Path(f"/proc/{wrapper.pid}/task/{wrapper.pid}/children").read_text().split()
            if len(children) != 1:
                raise AssertionError("npm wrapper did not have exactly one native child")
            child_pid = int(children[0])
            identity = process_identity(child_pid)
            if identity is None:
                raise AssertionError("native child exited before wrapper kill")
            child_start, _ = identity
            wrapper.kill()
            wrapper.wait(timeout=2)
            for _ in range(100):
                identity = process_identity(child_pid)
                child_exited = identity is None or identity[0] != child_start or identity[1] == "Z"
                if child_exited and listener_closed(port):
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("native child or HTTP listener survived launcher SIGKILL")
            print("PASS packaged npm parent pipe: wrapper SIGKILL closes native HTTP listener")
        finally:
            if wrapper.poll() is None:
                wrapper.kill()
                wrapper.wait(timeout=2)
            identity = process_identity(child_pid) if child_pid is not None else None
            if identity is not None and identity[0] == child_start and identity[1] != "Z":
                try:
                    os.kill(child_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    main()
