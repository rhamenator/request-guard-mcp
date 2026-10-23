#!/usr/bin/env python3
"""Exercise a published digest or private loaded image on a native runner."""

import argparse
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


IMAGE_RE = re.compile(r"^ghcr\.io/rhamenator/request-guard-mcp@sha256:[0-9a-f]{64}$")
PRIVATE_IMAGE_RE = re.compile(r"^request-guard-mcp:private-(amd64|arm64)$")
ROOT = Path(__file__).resolve().parents[1]


def command(*args: str, timeout: int = 60) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} {args[1]} failed: {result.stderr[-1000:]}")
    return result.stdout.strip()


def safe_logs(name: str, token: str) -> str:
    try:
        result = subprocess.run(("docker", "logs", name), capture_output=True, text=True, timeout=10)
        return (result.stdout + result.stderr)[-2000:].replace(token, "[REDACTED]")
    except subprocess.TimeoutExpired:
        return "container logs timed out"


def wait_for_listener(host: str, port: int, name: str, token: str) -> None:
    for _ in range(50):
        if command("docker", "inspect", "--format", "{{.State.Running}}", name) != "true":
            raise RuntimeError(f"container exited before ready: {safe_logs(name, token)}")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"container listener did not become ready: {safe_logs(name, token)}")


def verify_build_info(host: str, port: int, token: str, version: str, commit: str) -> None:
    request = urllib.request.Request(
        f"http://{host}:{port}/mcp",
        data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "model_info", "arguments": {}},
        }, separators=(",", ":")).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    # The bridge address belongs to this isolated runner, not an environment proxy.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=8) as response:
        if response.status != 200:
            raise RuntimeError(f"model_info returned HTTP {response.status}")
        result = json.load(response)
    build = result["result"]["structuredContent"]["build_info"]
    if (result.get("id") != 1 or build.get("version") != version
            or build.get("git_commit") != commit
            or not build.get("rust_version", "").startswith("rustc 1.99.1 (")):
        raise RuntimeError("running container build_info differs from expected source/toolchain")
    print(f"running container build_info: version {version}, full source commit and Rust 1.99.1 verified")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--image", help="immutable published GHCR index or platform digest")
    source.add_argument("--private-image", help="locally loaded unpublished candidate image")
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
        parser.error("expected commit must be a full lowercase Git SHA")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", args.expected_version):
        parser.error("expected version must be a Cargo-compatible version")
    if args.image and not IMAGE_RE.fullmatch(args.image):
        parser.error("image must be the immutable Request Guard GHCR sha256 digest")
    if args.private_image and (
        not PRIVATE_IMAGE_RE.fullmatch(args.private_image)
        or not args.private_image.endswith(args.arch)
    ):
        parser.error("private image must match the requested native architecture")
    image = args.image or args.private_image

    token = secrets.token_urlsafe(36)
    with tempfile.TemporaryDirectory(prefix="request-guard-native-smoke-") as directory:
        env_path = Path(directory) / "server.env"
        env_path.write_text(f"AUTH_TOKENS={token}\n", encoding="utf-8")
        env_path.chmod(0o600)
        name = f"request-guard-native-smoke-{os.getpid()}"
        started = False
        try:
            if args.image:
                command("docker", "pull", "--platform", f"linux/{args.arch}", image, timeout=180)
            actual_arch = command("docker", "image", "inspect", "--format", "{{.Architecture}}", image)
            if actual_arch != args.arch:
                raise RuntimeError(f"image architecture {actual_arch} differs from runner {args.arch}")
            command(
                "docker", "run", "-d", "--name", name, "--env-file", str(env_path),
                "--memory", "512m", "--cpus", "2", "--pids-limit", "128",
                "--security-opt", "no-new-privileges", "-e", "MCP__HOST=0.0.0.0",
                "-e", "MCP__PORT=8085", "-e", "MCP__LIMITS__MAX_REQUEST_BYTES=4096",
                image,
            )
            started = True
            host = command(
                "docker", "inspect", "--format",
                "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name,
            )
            if not host:
                raise RuntimeError("container bridge address is empty")
            wait_for_listener(host, 8085, name, token)
            verify_build_info(host, 8085, token, args.expected_version, args.expected_commit)
            probes = (
                ("adversarial_probe.py", "--url", f"http://{host}:8085", "--max-request-bytes", "4096"),
                ("adversarial_ws_probe.py", "--host", host, "--port", "8085", "--max-request-bytes", "4096"),
                ("adversarial_classifier_probe.py", "--url", f"http://{host}:8085"),
            )
            for filename, *options in probes:
                result = subprocess.run(
                    ("python3", str(ROOT / "scripts" / filename), *options),
                    input=token + "\n", text=True, capture_output=True, timeout=60,
                )
                if result.returncode != 0:
                    detail = (result.stdout + result.stderr)[-2000:].replace(token, "[REDACTED]")
                    raise RuntimeError(f"{filename} failed: {detail}; container: {safe_logs(name, token)}")
                print(f"{filename}: {result.stdout.strip()}")
            source_label = "published-digest" if args.image else "private-loaded"
            print(f"native {args.arch} {source_label} container smoke passed")
        finally:
            if started:
                prior_error = sys.exc_info()[0] is not None
                try:
                    removed = subprocess.run(("docker", "rm", "-f", name), capture_output=True, timeout=30)
                    if removed.returncode:
                        raise RuntimeError("could not remove smoke container")
                except subprocess.TimeoutExpired:
                    if not prior_error:
                        raise RuntimeError("timed out removing smoke container") from None
                    print("warning: timed out removing smoke container after probe failure", flush=True)
                except RuntimeError:
                    if not prior_error:
                        raise
                    print("warning: could not remove smoke container after probe failure", flush=True)


if __name__ == "__main__":
    main()
