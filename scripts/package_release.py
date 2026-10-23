#!/usr/bin/env python3
"""Package a native request-guard-mcp binary produced by GitHub Actions."""

from __future__ import annotations

import argparse
import hashlib
import re
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


def render_bundle_readme(template: str, version: str, source_commit: str, repository: str) -> str:
    expected = {"@RELEASE_LABEL@": 1, "@SOURCE_COMMIT@": 2, "@REPOSITORY@": 1}
    if any(template.count(key) != count for key, count in expected.items()):
        raise ValueError("bundle README must contain the expected identity placeholders")
    for key, value in (("@RELEASE_LABEL@", version), ("@SOURCE_COMMIT@", source_commit),
                       ("@REPOSITORY@", repository)):
        template = template.replace(key, value)
    return template


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--suffix", default="")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]*", args.version):
        parser.error("version must be a single safe filename component")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("source commit must be a full lowercase Git SHA-1")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("repository must be a GitHub owner/name pair")

    prefix = f"request-guard-mcp-{args.version}-{args.platform}"
    artifacts = Path("artifacts")
    stage = artifacts / prefix
    binary = Path("target") / args.target / "release" / f"request-guard-mcp{args.suffix}"
    if not binary.is_file():
        raise FileNotFoundError(f"release binary was not produced: {binary}")

    stage.mkdir(parents=True, exist_ok=False)
    shutil.copy2(binary, stage / binary.name)
    bundle_readme = render_bundle_readme(
        Path("README.bundle.md.in").read_text(encoding="utf-8"),
        args.version, args.source_commit, args.repository,
    )
    (stage / "README.md").write_text(bundle_readme, encoding="utf-8", newline="\n")
    shutil.copy2("INSTALL.md", stage / "INSTALL.md")
    shutil.copy2("LICENSE", stage / "LICENSE")
    shutil.copy2(".env.example", stage / ".env.example")
    shutil.copy2("Cargo.lock", stage / "Cargo.lock")
    (stage / "scripts").mkdir(exist_ok=True)
    shutil.copy2("scripts/postgres_minimize_legacy.sql", stage / "scripts/postgres_minimize_legacy.sql")

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
    with checksum.open("w", encoding="ascii", newline="\n") as output:
        output.write(f"{sha256(archive)} *{archive.name}\n")


if __name__ == "__main__":
    main()
