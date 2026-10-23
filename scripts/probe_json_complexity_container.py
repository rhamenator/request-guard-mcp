#!/usr/bin/env python3
"""Bound wide-JSON admission on a private native image under a 512 MiB limit."""

import argparse
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.request

from probe_json_complexity import run_probe


def docker(*args):
    result = subprocess.run(("docker", *args), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr[-500:]}")
    return result.stdout.strip()


def cgroup_peak(name):
    """Read the container's aggregate memory peak on a native cgroup-v2 runner."""
    return int(docker("exec", name, "cat", "/sys/fs/cgroup/memory.peak"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    args = parser.parse_args()
    image = f"request-guard-mcp:private-{args.arch}"
    if docker("image", "inspect", "--format", "{{.Architecture}}", image) != args.arch:
        raise RuntimeError("private image architecture differs from native runner")
    token = secrets.token_urlsafe(36)
    name = f"request-guard-json-complexity-{os.getpid()}"
    with tempfile.TemporaryDirectory(prefix="request-guard-json-container-") as folder:
        env_file = Path(folder) / "server.env"
        env_file.write_text(f"AUTH_TOKENS={token}\n", encoding="utf-8")
        env_file.chmod(0o600)
        try:
            docker(
                "run", "-d", "--name", name, "--network", "bridge",
                "--env-file", str(env_file), "--memory", "512m", "--cpus", "2",
                "--pids-limit", "128", "--security-opt", "no-new-privileges",
                "-e", "MCP__HOST=0.0.0.0", "-e", "MCP__PORT=8085",
                "-e", "MCP__LIMITS__MAX_CONNECTIONS=128", image,
            )
            host = docker("inspect", "--format",
                          "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
            pid = int(docker("inspect", "--format", "{{.State.Pid}}", name))
            if not host or pid <= 1:
                raise RuntimeError("private container has no reachable bridge address or PID")
            if not os.readlink(f"/proc/{pid}/exe").endswith("/request-guard-mcp"):
                raise RuntimeError("container PID is not the Request Guard server binary")
            memory_limit = int(docker("inspect", "--format", "{{.HostConfig.Memory}}", name))
            if memory_limit != 512 * 1024 * 1024:
                raise RuntimeError("private container does not have the expected 512 MiB limit")
            for attempt in range(50):
                try:
                    with urllib.request.urlopen(f"http://{host}:8085/health", timeout=1) as reply:
                        if reply.status == 200:
                            break
                except (OSError, ValueError):
                    pass
                if docker("inspect", "--format", "{{.State.Running}}", name) != "true":
                    raise RuntimeError("private container exited before readiness")
                time.sleep(0.2)
            else:
                raise RuntimeError("private container did not become ready")
            run_probe(host, 8085, token, pid, 64, burst_limit_kib=128 * 1024)
            memory_peak = cgroup_peak(name)
            if memory_peak > 256 * 1024 * 1024:
                raise RuntimeError("wide-JSON burst raised cgroup peak memory above 256 MiB")
            with urllib.request.urlopen(f"http://{host}:8085/health", timeout=2) as reply:
                if reply.status != 200:
                    raise RuntimeError("health failed after wide-JSON burst")
            if docker("inspect", "--format", "{{.State.Running}}", name) != "true":
                raise RuntimeError("private container exited after wide-JSON burst")
            if docker("inspect", "--format", "{{.State.OOMKilled}}", name) != "false":
                raise RuntimeError("private container was OOM-killed")
            if docker("inspect", "--format", "{{.RestartCount}}", name) != "0":
                raise RuntimeError("private container restarted")
            log_result = subprocess.run(("docker", "logs", name), capture_output=True,
                                        text=True, timeout=10, check=True)
            logs = log_result.stdout + log_result.stderr
            if token in logs or len(logs.encode()) > 65_536:
                raise RuntimeError("private container logs leaked bearer or grew unexpectedly")
            print(f"PASS private {args.arch} 512 MiB JSON complexity container; "
                  f"64 concurrent wide requests rejected, cgroup peak={memory_peak} bytes, "
                  "health recovered, no OOM/restart")
        finally:
            subprocess.run(("docker", "rm", "-f", name), capture_output=True,
                           text=True, timeout=15, check=False)


if __name__ == "__main__":
    main()
