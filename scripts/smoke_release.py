#!/usr/bin/env python3
"""Extract a release bundle and verify the packaged MCP server can start."""

from __future__ import annotations

import argparse
import os
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path


def find_archive(directory: Path) -> Path:
    archives = list(directory.glob("*.zip")) + list(directory.glob("*.tar.gz"))
    if len(archives) != 1:
        raise RuntimeError(f"expected one release archive, found: {archives}")
    return archives[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    archive = find_archive(args.artifacts)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as package:
                package.extractall(root)
        else:
            with tarfile.open(archive) as package:
                package.extractall(root, filter="data")

        matches = list(root.rglob(args.binary))
        if len(matches) != 1:
            raise RuntimeError(f"expected one {args.binary}, found: {matches}")
        lockfiles = list(root.rglob("Cargo.lock"))
        if len(lockfiles) != 1:
            raise RuntimeError(f"expected packaged Cargo.lock inventory, found: {lockfiles}")
        guides = list(root.rglob("INSTALL.md"))
        if len(guides) != 1:
            raise RuntimeError(f"expected one packaged INSTALL.md, found: {guides}")

        example = matches[0].parent / ".env.example"
        if not example.is_file():
            raise RuntimeError("release bundle is missing .env.example")
        settings = example.read_text(encoding="utf-8")
        for old, new in (
            ("AUTH_TOKENS=replace_me_with_a_strong_token", "AUTH_TOKENS=release-smoke-token-with-at-least-32-characters"),
            ("MCP__HOST=0.0.0.0", "MCP__HOST=127.0.0.1"),
            ("MCP__PORT=8085", f"MCP__PORT={args.port}"),
        ):
            if old not in settings:
                raise RuntimeError(f"release .env.example is missing expected setting: {old.split('=')[0]}")
            settings = settings.replace(old, new, 1)
        dotenv = matches[0].parent / ".env"
        dotenv.write_text(settings, encoding="utf-8")
        dotenv.chmod(0o600)
        environment = os.environ.copy()
        for name in ("AUTH_TOKENS", "MCP__HOST", "MCP__PORT"):
            environment.pop(name, None)
        process = subprocess.Popen(
            [str(matches[0])],
            cwd=matches[0].parent,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 20
            url = f"http://127.0.0.1:{args.port}/health"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"packaged server exited with {process.returncode}")
                try:
                    with urllib.request.urlopen(url, timeout=1) as response:
                        if response.status == 200:
                            return
                except OSError:
                    time.sleep(0.25)
            raise TimeoutError(f"packaged server did not become healthy at {url}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
