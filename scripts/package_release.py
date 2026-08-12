#!/usr/bin/env python3
"""Package a native request-guard-mcp binary produced by GitHub Actions."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import tarfile
import zipfile
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--suffix", default="")
    args = parser.parse_args()

    prefix = f"request-guard-mcp-{args.version}-{args.platform}"
    artifacts = Path("artifacts")
    stage = artifacts / prefix
    binary = Path("target") / args.target / "release" / f"request-guard-mcp{args.suffix}"
    if not binary.is_file():
        raise FileNotFoundError(f"release binary was not produced: {binary}")

    stage.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, stage / binary.name)
    shutil.copy2("README.md", stage / "README.md")
    shutil.copy2("LICENSE", stage / "LICENSE")
    shutil.copy2(".env.example", stage / ".env.example")
    shutil.copy2("Cargo.lock", stage / "Cargo.lock")

    if args.platform.startswith("windows-"):
        archive = artifacts / f"{prefix}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    output.write(path, path.relative_to(artifacts))
    else:
        archive = artifacts / f"{prefix}.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(stage, arcname=prefix)

    checksum = archive.with_name(f"{archive.name}.sha256")
    checksum.write_text(f"{sha256(archive)} *{archive.name}\n", encoding="ascii")


if __name__ == "__main__":
    main()
