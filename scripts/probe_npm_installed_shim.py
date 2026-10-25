#!/usr/bin/env python3
"""Prove a clean npm-installed HTTP shim cleans up after its Node process is killed."""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from probe_npm_parent_pipe_portable import WindowsProcess, posix_identity


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


def process_running(pid, identity=None, handle=None):
    if handle is not None:
        return handle.running()
    current = posix_identity(pid)
    return current is not None and current[0] == identity[0] and not current[1].startswith("Z")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if sys.platform == "darwin":
        platform = "macos-arm64" if os.uname().machine == "arm64" else "macos-x64"
        binary_name = "request-guard-mcp"
    elif sys.platform == "win32":
        platform, binary_name = "windows-x64", "request-guard-mcp.exe"
    else:
        platform, binary_name = "linux-x64", "request-guard-mcp"

    launcher_source = Path(__file__).resolve().parents[1] / "npm/bin/request-guard-mcp.js"
    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError("npm is required for installed-shim qualification")
    with tempfile.TemporaryDirectory(prefix="rg-npm-installed-shim-") as cwd:
        root = Path(cwd)
        package = root / "package"
        launcher = package / "bin/request-guard-mcp.js"
        vendor = package / "vendor" / platform / binary_name
        launcher.parent.mkdir(parents=True)
        vendor.parent.mkdir(parents=True)
        shutil.copyfile(launcher_source, launcher)
        shutil.copyfile(binary, vendor)
        launcher.chmod(0o755)
        vendor.chmod(0o755)
        (package / "package.json").write_text(json.dumps({
            "name": "request-guard-mcp-shim-probe", "version": "0.0.0",
            "private": True, "bin": {"request-guard-mcp": "bin/request-guard-mcp.js"},
            "files": ["bin/", "vendor/"],
        }))
        packed = subprocess.run(
            [npm, "pack", "--offline", "--ignore-scripts", "--silent", "--pack-destination", str(root)],
            cwd=package, capture_output=True, text=True, check=True,
        )
        tarball = root / packed.stdout.strip().splitlines()[-1]
        install = root / "install"
        subprocess.run(
            [npm, "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund",
             "--prefix", str(install), str(tarball)],
            cwd=root, capture_output=True, text=True, check=True,
        )
        installed = install / "node_modules" / "request-guard-mcp-shim-probe"
        assert (installed / "vendor" / platform / binary_name).is_file()
        shim = install / "node_modules" / ".bin" / (
            "request-guard-mcp.cmd" if sys.platform == "win32" else "request-guard-mcp"
        )
        assert shim.is_file()

        preload = root / "record-process.cjs"
        preload.write_text(
            "const cp=require('node:child_process');const fs=require('node:fs');"
            "fs.writeFileSync(process.env.RG_TEST_WRAPPER_PID+'.tmp',String(process.pid));"
            "fs.renameSync(process.env.RG_TEST_WRAPPER_PID+'.tmp',process.env.RG_TEST_WRAPPER_PID);"
            "const spawn=cp.spawn;cp.spawn=function(...args){const child=spawn(...args);"
            "if(child.pid){const file=process.env.RG_TEST_CHILD_PID;"
            "fs.writeFileSync(file+'.tmp',String(child.pid));fs.renameSync(file+'.tmp',file);}"
            "return child;};\n"
        )
        port = free_port()
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"PATH", "TMPDIR", "TEMP", "SYSTEMROOT", "WINDIR",
                                  "COMSPEC", "USERPROFILE", "SYSTEMDRIVE"}}
        env.update({"HOME": cwd, "MCP__HOST": "127.0.0.1", "MCP__PORT": str(port),
                    "MCP__AUTH__ENABLED": "true",
                    "AUTH_TOKENS": "synthetic-installed-shim-token-abcdefghijklmnopqrstuvwxyz123456",
                    "LOG_LEVEL": "error", "NODE_OPTIONS": f"--require={preload}",
                    "RG_TEST_WRAPPER_PID": str(root / "wrapper.pid"),
                    "RG_TEST_CHILD_PID": str(root / "child.pid")})
        command = (["cmd.exe", "/d", "/c", str(shim)] if sys.platform == "win32" else [str(shim)])
        outer = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wrapper_pid = child_pid = None
        wrapper_handle = child_handle = None
        wrapper_identity = child_identity = None
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if wrapper_pid is None and (root / "wrapper.pid").exists():
                    wrapper_pid = int((root / "wrapper.pid").read_text())
                    if sys.platform == "win32":
                        wrapper_handle = WindowsProcess(wrapper_pid)
                    else:
                        wrapper_identity = posix_identity(wrapper_pid)
                if child_pid is None and (root / "child.pid").exists():
                    child_pid = int((root / "child.pid").read_text())
                    if sys.platform == "win32":
                        child_handle = WindowsProcess(child_pid)
                    else:
                        child_identity = posix_identity(child_pid)
                if wrapper_pid and child_pid and healthy(port):
                    break
                if outer.poll() is not None:
                    raise AssertionError("installed shim exited before HTTP health")
                time.sleep(0.05)
            else:
                raise AssertionError("installed shim did not start HTTP listener")
            assert process_running(wrapper_pid, wrapper_identity, wrapper_handle)
            assert process_running(child_pid, child_identity, child_handle)
            if wrapper_handle is not None:
                wrapper_handle.terminate()
            else:
                os.kill(wrapper_pid, signal.SIGKILL)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if not process_running(child_pid, child_identity, child_handle) and not healthy(port):
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("native child or listener survived installed wrapper kill")
            print(f"PASS installed npm shim on {sys.platform}: native child/listener exited")
        finally:
            if wrapper_handle is not None:
                wrapper_handle.terminate()
                wrapper_handle.close()
            elif wrapper_pid and wrapper_identity and process_running(wrapper_pid, wrapper_identity):
                os.kill(wrapper_pid, signal.SIGTERM)
            if child_handle is not None:
                child_handle.terminate()
                child_handle.close()
            elif child_pid and child_identity and process_running(child_pid, child_identity):
                os.kill(child_pid, signal.SIGTERM)
            if outer.poll() is None:
                outer.kill()
            outer.wait(timeout=2)


if __name__ == "__main__":
    main()
