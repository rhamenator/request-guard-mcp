#!/usr/bin/env python3
"""Exercise self-contained native bundle docs and release archive rejection paths."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from package_release import render_bundle_readme

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
VERSION = "v1.0.0-rc.1"
REPOSITORY = "rhamenator/request-guard-mcp"


def fixture(root: Path, *, platform: str = "linux-x64", suffix: str = "", extra_link: str = "") -> tuple[list[str], Path]:
    (root / "scripts").mkdir()
    binary_dir = root / "target/test/release"
    binary_dir.mkdir(parents=True)
    (binary_dir / f"request-guard-mcp{suffix}").write_bytes(b"test-binary")
    for name in ("README.bundle.md.in", "INSTALL.md", "LICENSE", ".env.example", "Cargo.lock"):
        shutil.copy2(ROOT / name, root / name)
    shutil.copy2(ROOT / "scripts/postgres_minimize_legacy.sql", root / "scripts/postgres_minimize_legacy.sql")
    if extra_link:
        with (root / "README.bundle.md.in").open("a", encoding="utf-8") as output:
            output.write(f"\n[extra]({extra_link})\n")
    subprocess.run([
        "python3", str(ROOT / "scripts/package_release.py"),
        "--version", VERSION, "--target", "test", "--platform", platform,
        "--suffix", suffix, "--source-commit", COMMIT,
        "--repository", REPOSITORY,
    ], cwd=root, check=True)
    folder = f"request-guard-mcp-{VERSION}-{platform}"
    ext = "zip" if suffix else "tar.gz"
    command = [
        "python3", str(ROOT / "scripts/verify_release_archive.py"),
        "--archive", f"artifacts/{folder}.{ext}",
        "--sidecar", f"artifacts/{folder}.{ext}.sha256",
        "--staging-binary", f"artifacts/{folder}/request-guard-mcp{suffix}",
        "--folder", folder, "--binary", f"request-guard-mcp{suffix}",
        "--version", VERSION, "--source-commit", COMMIT,
        "--repository", REPOSITORY,
    ]
    return command, root / "artifacts" / f"{folder}.{ext}"


def check(command: list[str], root: Path, *, success: bool, message: str = "") -> None:
    output = f"verified-{len(list(root.glob('verified-*')))}"
    result = subprocess.run(command + ["--output", output], cwd=root,
                            capture_output=True, text=True)
    if success:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0 and message in result.stderr, result.stderr


def main() -> None:
    template = (ROOT / "README.bundle.md.in").read_text(encoding="utf-8")
    for broken in (template.replace("@REPOSITORY@", "gone"),
                   template + "\n@SOURCE_COMMIT@"):
        try:
            render_bundle_readme(broken, VERSION, COMMIT, REPOSITORY)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid bundle identity placeholders were accepted")
    with tempfile.TemporaryDirectory() as path:
        root = Path(path)
        command, _ = fixture(root)
        check(command, root, success=True)
        check(["0" * 40 if item == COMMIT else item for item in command], root,
              success=False, message="stale release identity")
    with tempfile.TemporaryDirectory() as path:
        root = Path(path)
        command, _ = fixture(root, platform="windows-x64", suffix=".exe")
        check(command, root, success=True)
    for target, error in (("missing.md", "missing file"), ("../outside.md", "unsafe relative link")):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root / "outside.md").write_text("outside")
            command, _ = fixture(root, extra_link=target)
            check(command, root, success=False, message=error)
    with tempfile.TemporaryDirectory() as path:
        root = Path(path)
        command, archive = fixture(root)
        rewritten = root / "rewritten.tar.gz"
        with tarfile.open(archive, "r:gz") as source, tarfile.open(rewritten, "w:gz") as output:
            for member in source.getmembers():
                data = source.extractfile(member) if member.isfile() else None
                output.addfile(member, data)
            link = tarfile.TarInfo(f"request-guard-mcp-{VERSION}-linux-x64/linked-readme")
            link.type = tarfile.SYMTYPE
            link.linkname = "README.md"
            output.addfile(link)
        rewritten.replace(archive)
        archive.with_name(f"{archive.name}.sha256").write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()} *{archive.name}\n"
        )
        check(command, root, success=False, message="must not contain links")
    print("PASS native bundle docs identity, Linux/Windows archive and negative links")


if __name__ == "__main__":
    main()
