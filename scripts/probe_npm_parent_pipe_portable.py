#!/usr/bin/env python3
"""Check packaged HTTP child cleanup after an npm wrapper is forcibly killed."""

import argparse
import ctypes
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


def posix_identity(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "lstart=", "-o", "stat="],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    parts = result.stdout.strip().split()
    return " ".join(parts[:5]), parts[5] if len(parts) > 5 else ""


class WindowsProcess:
    """Hold a process handle so its PID cannot be mistaken for a reused process."""

    def __init__(self, pid):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
        kernel32.TerminateProcess.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        self.kernel32 = kernel32
        self.handle = kernel32.OpenProcess(0x1000 | 0x0001, 0, pid)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "OpenProcess failed")

    def running(self):
        status = ctypes.c_uint32()
        if not self.kernel32.GetExitCodeProcess(self.handle, ctypes.byref(status)):
            raise OSError(ctypes.get_last_error(), "GetExitCodeProcess failed")
        return status.value == 259  # STILL_ACTIVE

    def terminate(self):
        if self.running() and not self.kernel32.TerminateProcess(self.handle, 1):
            raise OSError(ctypes.get_last_error(), "TerminateProcess failed")

    def close(self):
        self.kernel32.CloseHandle(self.handle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if sys.platform == "darwin":
        platform = ("macos-arm64" if os.uname().machine == "arm64" else "macos-x64", "request-guard-mcp")
    else:
        platform = {
            "linux": ("linux-x64", "request-guard-mcp"),
            "win32": ("windows-x64", "request-guard-mcp.exe"),
        }[sys.platform]
    launcher_source = Path(__file__).resolve().parents[1] / "npm/bin/request-guard-mcp.js"
    with tempfile.TemporaryDirectory(prefix="rg-npm-parent-pipe-") as cwd:
        root = Path(cwd)
        launcher = root / "bin/request-guard-mcp.js"
        vendor = root / "vendor" / platform[0] / platform[1]
        launcher.parent.mkdir()
        vendor.parent.mkdir(parents=True)
        shutil.copyfile(launcher_source, launcher)
        shutil.copyfile(binary, vendor)
        launcher.chmod(0o755)
        vendor.chmod(0o755)
        pid_file = root / "child.pid"
        preload = root / "record-child.cjs"
        preload.write_text(
            "const cp=require('node:child_process');const fs=require('node:fs');"
            "const spawn=cp.spawn;cp.spawn=function(...args){const child=spawn(...args);"
            "if(child.pid)fs.writeFileSync(process.env.RG_TEST_CHILD_PID,String(child.pid));"
            "return child;};\n"
        )
        port = free_port()
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"PATH", "TMPDIR", "TEMP", "SYSTEMROOT", "WINDIR",
                                  "COMSPEC", "USERPROFILE", "SYSTEMDRIVE"}}
        env.update({"HOME": cwd, "MCP__HOST": "127.0.0.1", "MCP__PORT": str(port),
                    "MCP__AUTH__ENABLED": "true",
                    "AUTH_TOKENS": "synthetic-parent-pipe-token-abcdefghijklmnopqrstuvwxyz123456",
                    "LOG_LEVEL": "error",
                    "RG_TEST_CHILD_PID": str(pid_file)})
        wrapper = subprocess.Popen(["node", "--require", str(preload), str(launcher)], cwd=cwd, env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        child_pid = None
        identity = None
        handle = None
        try:
            startup_deadline = time.monotonic() + 20
            while time.monotonic() < startup_deadline:
                if child_pid is None and pid_file.exists():
                    child_pid = int(pid_file.read_text())
                    if sys.platform == "win32":
                        handle = WindowsProcess(child_pid)
                        if not handle.running():
                            raise AssertionError("native child exited before HTTP health")
                    else:
                        identity = posix_identity(child_pid)
                        if identity is None or identity[1].startswith("Z"):
                            raise AssertionError("native child exited before HTTP health")
                if child_pid is not None and healthy(port):
                    break
                if wrapper.poll() is not None:
                    raise AssertionError("npm wrapper exited before HTTP health was available")
                time.sleep(0.05)
            else:
                raise AssertionError("npm wrapper did not start HTTP listener")
            wrapper.kill()
            wrapper.wait(timeout=2)
            exit_deadline = time.monotonic() + 15
            child_exited = False
            health_still_served = True
            while time.monotonic() < exit_deadline:
                if sys.platform == "win32":
                    child_exited = not handle.running()
                else:
                    current = posix_identity(child_pid)
                    child_exited = current is None or current[0] != identity[0] or current[1].startswith("Z")
                health_still_served = healthy(port)
                if child_exited and not health_still_served:
                    break
                time.sleep(0.05)
            else:
                raise AssertionError(
                    "native child or HTTP listener survived wrapper forced kill: "
                    f"child_exited={child_exited}, health_still_served={health_still_served}"
                )
            print(f"PASS packaged npm parent pipe on {sys.platform}: native child/listener exited")
        finally:
            if wrapper.poll() is None:
                wrapper.kill()
                wrapper.wait(timeout=2)
            if child_pid is None and pid_file.exists():
                child_pid = int(pid_file.read_text())
                if sys.platform == "win32":
                    handle = WindowsProcess(child_pid)
                else:
                    identity = posix_identity(child_pid)
            if handle is not None:
                try:
                    handle.terminate()
                finally:
                    handle.close()
            elif child_pid is not None and identity is not None:
                current = posix_identity(child_pid)
                if current is not None and current[0] == identity[0] and not current[1].startswith("Z"):
                    os.kill(child_pid, signal.SIGTERM)


if __name__ == "__main__":
    main()
