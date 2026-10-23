#!/usr/bin/env python3
"""Verify the exact native asset set immediately before GitHub Release upload."""

import argparse
import hashlib
from pathlib import Path
import re


PLATFORMS = {
    "windows-x64": "zip",
    "linux-x64": "tar.gz",
    "linux-x64-musl": "tar.gz",
    "macos-x64": "tar.gz",
    "macos-arm64": "tar.gz",
}


def verify(artifacts: Path, version: str) -> None:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", version):
        raise ValueError("invalid release version")
    expected = {
        f"request-guard-mcp-{version}-{platform}.{suffix}"
        for platform, suffix in PLATFORMS.items()
    }
    expected |= {f"{name}.sha256" for name in tuple(expected)}
    actual = {entry.name for entry in artifacts.iterdir()}
    if actual != expected or any(not entry.is_file() or entry.is_symlink() for entry in artifacts.iterdir()):
        raise ValueError(f"release asset set mismatch: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")

    for name in sorted(expected):
        if name.endswith(".sha256"):
            continue
        archive = artifacts / name
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        sidecar = (artifacts / f"{name}.sha256").read_text(encoding="ascii")
        if sidecar != f"{digest} *{name}\n":
            raise ValueError(f"checksum sidecar mismatch: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    verify(args.artifacts, args.version)
    print("Verified exact five native archives and five SHA256 sidecars")


if __name__ == "__main__":
    main()
