#!/usr/bin/env python3
"""Negative controls for the final GitHub Release upload manifest."""

import hashlib
from pathlib import Path
import tempfile

from verify_release_manifest import PLATFORMS, verify


def expect_rejected(root: Path, version: str) -> None:
    try:
        verify(root, version)
    except ValueError:
        return
    raise AssertionError("invalid release manifest was accepted")


def main() -> None:
    # The upload action uses a separate YAML list; keep it aligned with the
    # exact set verified before publication.
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"
    release_job = workflow.read_text().split("  create-release:\n", 1)[1]
    upload = release_job.split("          files: |\n", 1)[1].split("          generate_release_notes:", 1)[0]
    globs = {line.strip() for line in upload.splitlines() if line.strip()}
    expected_globs = {
        f"artifacts/*-{platform}.{suffix}"
        for platform, suffix in PLATFORMS.items()
    }
    expected_globs |= {f"{name}.sha256" for name in tuple(expected_globs)}
    assert globs == expected_globs, (globs, expected_globs)

    version = "v1.0.0"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        names = [f"request-guard-mcp-{version}-{platform}.{suffix}" for platform, suffix in PLATFORMS.items()]
        for name in names:
            data = name.encode()
            (root / name).write_bytes(data)
            (root / f"{name}.sha256").write_text(f"{hashlib.sha256(data).hexdigest()} *{name}\n")
        verify(root, version)
        (root / names[0]).write_bytes(b"corrupt")
        expect_rejected(root, version)
        (root / names[0]).write_bytes(names[0].encode())
        (root / f"{names[1]}.sha256").unlink()
        expect_rejected(root, version)
        (root / f"{names[1]}.sha256").write_text(f"{hashlib.sha256(names[1].encode()).hexdigest()} *{names[1]}\n")
        (root / "unexpected.txt").write_text("extra")
        expect_rejected(root, version)
        (root / "unexpected.txt").unlink()
        (root / names[2]).unlink()
        expect_rejected(root, version)
        expect_rejected(root, "1.0.0")
    print("PASS exact release asset manifest and negative controls")


if __name__ == "__main__":
    main()
