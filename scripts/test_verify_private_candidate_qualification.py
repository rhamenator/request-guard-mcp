#!/usr/bin/env python3
"""Exercise the full private gate with mocked GitHub API and artifact bytes."""

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from private_candidate_gate import NATIVE_SKIPPED_JOBS, PLATFORMS, REQUIRED_JOBS, WORKFLOWS
from verify_private_candidate_qualification import qualify
from write_private_candidate_evidence import digest


REPO = "owner/request-guard-mcp"
SOURCE = "a" * 40
LABEL = "v1.1.0-rc.2"
TAG_OBJECT = "b" * 40
RUNS = {"native": 123, "npm": 456, "container": 789}
ATTEMPTS = {"native": 1, "npm": 1, "container": 1}
TARBALL_BYTES = b"npm candidate"


def metadata(kind, platform, extra):
    return {
        "schema": 1, "kind": kind, "platform": platform,
        "candidate_label": LABEL, "source_sha": SOURCE,
        "run_id": RUNS[kind], "run_attempt": ATTEMPTS[kind], **extra,
    }


def write_native(directory: Path, platform: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    ext = "zip" if platform == "windows-x64" else "tar.gz"
    name = f"request-guard-mcp-{LABEL}-{platform}.{ext}"
    archive = directory / name
    archive.write_bytes(f"native {platform}".encode())
    checksum = digest(archive)
    (directory / f"{name}.sha256").write_text(f"{checksum} *{name}\n")
    evidence = metadata("native", platform, {"archive": name, "archive_sha256": checksum})
    (directory / f"private-evidence-{platform}.json").write_text(json.dumps(evidence))


def fake_download(_repo, run_id, name, directory):
    directory.mkdir(parents=True, exist_ok=False)
    if run_id == RUNS["native"]:
        write_native(directory, name.removeprefix("request-guard-mcp-"))
    elif run_id == RUNS["npm"]:
        assets = directory / "assets"
        for platform in PLATFORMS:
            write_native(assets, platform)
        npm = directory / "npm"
        npm.mkdir()
        name = f"request-guard-mcp-{LABEL.removeprefix('v')}.tgz"
        tarball = npm / name
        tarball.write_bytes(TARBALL_BYTES)
        evidence = metadata("npm", None, {
            "tarball": name, "tarball_sha256": digest(tarball),
            "release_run_id": RUNS["native"], "release_run_attempt": 1,
        })
        (npm / "private-evidence.json").write_text(json.dumps(evidence))
    else:
        arch = name.removeprefix("private-container-inputs-")
        inventory = {}
        for stage in ("builder", "runtime", "toolchain"):
            path = directory / f"{stage}.txt"
            path.write_text(f"{stage} {arch}")
            inventory[f"{stage}_sha256"] = digest(path)
        evidence = metadata("container", arch, {
            "image_id": "sha256:" + "c" * 64, **inventory,
        })
        (directory / "private-evidence.json").write_text(json.dumps(evidence))


def responses(npm_digest):
    message = (
        "Request Guard MCP qualification v1\n"
        f"candidate_label={LABEL}\nsource_sha={SOURCE}\n"
        "release_run=123/1\nnpm_run=456/1\ncontainer_run=789/1\n"
        f"npm_tarball_sha256={npm_digest}\n"
    )
    result = {
        f"repos/{REPO}/git/ref/tags/{LABEL}": {
            "ref": f"refs/tags/{LABEL}", "object": {"type": "tag", "sha": TAG_OBJECT},
        },
        f"repos/{REPO}/git/tags/{TAG_OBJECT}": {
            "sha": TAG_OBJECT, "tag": LABEL,
            "object": {"type": "commit", "sha": SOURCE}, "message": message,
        },
    }
    names = {
        "native": [f"request-guard-mcp-{p}" for p in PLATFORMS],
        "npm": ["private-npm-candidate-inputs"],
        "container": ["private-container-inputs-amd64", "private-container-inputs-arm64"],
    }
    for kind, run_id in RUNS.items():
        base = f"repos/{REPO}/actions/runs/{run_id}"
        result[base] = {
            "id": run_id, "run_attempt": 1, "path": WORKFLOWS[kind],
            "event": "workflow_dispatch", "conclusion": "success", "head_sha": SOURCE,
            "head_repository": {"full_name": REPO}, "repository": {"full_name": REPO},
        }
        jobs = [{"name": name, "conclusion": "success", "run_attempt": 1,
                 "head_sha": SOURCE} for name in REQUIRED_JOBS[kind]]
        if kind == "native":
            jobs.extend({"name": name, "conclusion": "skipped", "run_attempt": 1,
                         "head_sha": SOURCE} for name in NATIVE_SKIPPED_JOBS)
        result[f"{base}/attempts/1/jobs?per_page=100"] = {
            "total_count": len(jobs), "jobs": jobs,
        }
        artifacts = [{"id": i + 1, "name": name, "expired": False,
                      "workflow_run": {"id": run_id, "head_sha": SOURCE}}
                     for i, name in enumerate(names[kind])]
        result[f"{base}/artifacts?per_page=100"] = {
            "total_count": len(artifacts), "artifacts": artifacts,
        }
    return result


def main():
    empty_pin = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("verify_private_candidate_qualification.py"))],
        env={**os.environ, "REQUEST_GUARD_EXPECTED_TAG_OBJECT_SHA": ""},
        capture_output=True, text=True, check=False,
    )
    assert empty_pin.returncode != 0
    assert "expected tag object SHA is empty" in empty_pin.stderr
    import hashlib
    sha = hashlib.sha256(TARBALL_BYTES).hexdigest()
    data = responses(sha)
    with TemporaryDirectory() as directory:
        output = Path(directory) / "verified-native"
        result = qualify(repository=REPO, label=LABEL, source_sha=SOURCE,
                         api=data.__getitem__, download=fake_download,
                         native_output_dir=output)
        assert result["tag_object_sha"] == TAG_OBJECT
        assert result["npm_tarball_sha256"] == sha
        assert set(result["native_archives_sha256"]) == set(PLATFORMS)
        assert set(result["container_input_sha256"]) == {"amd64", "arm64"}
        assert len(list(output.iterdir())) == 10
        for platform in PLATFORMS:
            extension = "zip" if platform == "windows-x64" else "tar.gz"
            archive = output / f"request-guard-mcp-{LABEL}-{platform}.{extension}"
            assert digest(archive) == result["native_archives_sha256"][platform]
    wrong = responses("0" * 64)
    try:
        qualify(repository=REPO, label=LABEL, source_sha=SOURCE,
                expected_tag_object_sha="0" * 40,
                api=data.__getitem__, download=fake_download)
    except ValueError as error:
        assert "tag object changed" in str(error)
    else:
        raise AssertionError("replaced tag object passed")
    try:
        qualify(repository=REPO, label=LABEL, source_sha=SOURCE,
                api=wrong.__getitem__, download=fake_download)
    except ValueError as error:
        assert "tag npm tarball digest differs" in str(error)
    else:
        raise AssertionError("wrong tag npm digest passed")
    print("PASS private qualification integration: exact three runs and artifact bytes")


if __name__ == "__main__":
    main()
