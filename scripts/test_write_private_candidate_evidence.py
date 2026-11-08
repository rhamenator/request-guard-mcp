#!/usr/bin/env python3
"""Check candidate metadata generation and native checksum rejection."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


SCRIPT = Path(__file__).with_name("write_private_candidate_evidence.py")
SOURCE_SHA = "a" * 40
LABEL = "v1.1.0-rc.2"


def invoke(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *(str(arg) for arg in args)],
        env={**os.environ, "GITHUB_SHA": SOURCE_SHA, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"},
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        archive = root / "request-guard-mcp-v1.1.0-rc.2-linux-x64.tar.gz"
        archive.write_bytes(b"native archive")
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        sidecar = root / f"{archive.name}.sha256"
        sidecar.write_text(f"{archive_hash} *{archive.name}\n")
        output = root / "evidence.json"

        result = invoke("--kind", "native", "--label", LABEL, "--platform", "linux-x64",
                        "--archive", archive, "--sidecar", sidecar, "--output", output)
        assert result.returncode == 0, result.stderr
        data = json.loads(output.read_text())
        assert data == {
            "archive": archive.name, "archive_sha256": archive_hash,
            "candidate_label": LABEL, "kind": "native", "platform": "linux-x64",
            "run_attempt": 2, "run_id": 123, "schema": 1, "source_sha": SOURCE_SHA,
        }

        sidecar.write_text(f"{'0' * 64} *{archive.name}\n")
        result = invoke("--kind", "native", "--label", LABEL, "--platform", "linux-x64",
                        "--archive", archive, "--sidecar", sidecar, "--output", output)
        assert result.returncode != 0 and "disagree" in result.stderr

        result = invoke("--kind", "npm", "--label", LABEL, "--tarball", archive,
                        "--release-run-id", 456, "--release-run-attempt", 1,
                        "--output", output)
        assert result.returncode == 0, result.stderr
        data = json.loads(output.read_text())
        assert data["tarball_sha256"] == archive_hash
        assert (data["release_run_id"], data["release_run_attempt"]) == (456, 1)

        for name in ("builder", "runtime", "toolchain"):
            (root / f"{name}.txt").write_text(name)
        result = invoke("--kind", "container", "--label", LABEL, "--platform", "amd64",
                        "--image-id", f"sha256:{'b' * 64}",
                        "--builder", root / "builder.txt", "--runtime", root / "runtime.txt",
                        "--toolchain", root / "toolchain.txt", "--output", output)
        assert result.returncode == 0, result.stderr
        data = json.loads(output.read_text())
        assert data["image_id"] == f"sha256:{'b' * 64}"
        assert all(data[f"{name}_sha256"] for name in ("builder", "runtime", "toolchain"))

        result = invoke("--kind", "npm", "--label", "v1.1.0+bad", "--tarball", archive,
                        "--release-run-id", 456, "--release-run-attempt", 1,
                        "--output", output)
        assert result.returncode != 0 and "invalid candidate label" in result.stderr
    print("PASS private candidate evidence: source, label, digests and checksum rejection")


if __name__ == "__main__":
    main()
