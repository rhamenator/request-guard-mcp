#!/usr/bin/env python3
"""Verify a release sidecar and smoke-test-ready binary from a clean extraction."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import tarfile
import zipfile


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def check_member(name: str, folder: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != folder:
        raise ValueError(f"archive contains an unexpected path: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--staging-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--folder", required=True)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()

    line = args.sidecar.read_text(encoding="ascii").strip()
    expected = f"{digest(args.archive)} *{args.archive.name}"
    if line != expected:
        raise ValueError("release archive does not match its SHA-256 sidecar")
    if args.output.exists():
        raise ValueError("extract into a new, empty output path")
    args.output.mkdir(parents=True)

    if args.archive.suffix == ".zip":
        with zipfile.ZipFile(args.archive) as package:
            for member in package.infolist():
                check_member(member.filename, args.folder)
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("archive must not contain symlinks")
            package.extractall(args.output)
    elif args.archive.name.endswith(".tar.gz"):
        with tarfile.open(args.archive, "r:gz") as package:
            for member in package.getmembers():
                check_member(member.name, args.folder)
            package.extractall(args.output, filter="data")
    else:
        raise ValueError("expected a .zip or .tar.gz release archive")

    extracted = args.output / args.folder / args.binary
    if not extracted.is_file():
        raise ValueError("release archive is missing its expected binary")
    if digest(extracted) != digest(args.staging_binary):
        raise ValueError("extracted binary differs from the built staging binary")
    migration = args.output / args.folder / "scripts/postgres_minimize_legacy.sql"
    if not migration.is_file():
        raise ValueError("release archive is missing the PostgreSQL legacy migration")
    if migration.read_text(encoding="utf-8") != Path(
        "scripts/postgres_minimize_legacy.sql"
    ).read_text(encoding="utf-8"):
        raise ValueError("packaged PostgreSQL legacy migration differs from source")
    print(f"PASS verified archive and extracted binary: {extracted}")


if __name__ == "__main__":
    main()
