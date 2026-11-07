#!/usr/bin/env python3
"""Verify unpublished native, npm and container evidence for an annotated tag."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from typing import Callable

from private_candidate_gate import (
    PLATFORMS, fetch_qualification_run, load_annotated_tag, require,
    validate_artifact_listing, verify_container_files, verify_native_files,
    verify_npm_files,
)


def github_api(path: str) -> dict:
    require(bool(os.environ.get("GH_TOKEN")), "GH_TOKEN is required for qualification")
    response = subprocess.run(["gh", "api", path], capture_output=True, text=True, check=True)
    return json.loads(response.stdout)


def download_artifact(repository: str, run_id: int, name: str, destination: Path) -> None:
    require(bool(os.environ.get("GH_TOKEN")), "GH_TOKEN is required for artifact download")
    destination.mkdir(parents=True, exist_ok=False)
    subprocess.run(
        ["gh", "run", "download", str(run_id), "--repo", repository,
         "--name", name, "--dir", str(destination)],
        check=True, capture_output=True, text=True,
    )


def qualify(
    *, repository: str, label: str, source_sha: str,
    api: Callable[[str], dict] = github_api,
    download: Callable[[str, int, str, Path], None] = download_artifact,
    expected_tag_object_sha: str | None = None,
) -> dict:
    tag_sha, annotation = load_annotated_tag(
        repository=repository, label=label, source_sha=source_sha,
        api=api, expected_tag_object_sha=expected_tag_object_sha,
    )
    runs: dict[str, dict] = {}
    artifacts: dict[str, dict[str, int]] = {}
    for kind, run_key in (("native", "release"), ("npm", "npm"), ("container", "container")):
        run_id = annotation[f"{run_key}_run_id"]
        attempt = annotation[f"{run_key}_run_attempt"]
        run, _jobs = fetch_qualification_run(
            kind, repository=repository, source_sha=source_sha,
            run_id=run_id, run_attempt=attempt, api=api,
        )
        runs[kind] = run
        page = api(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100")
        artifacts[kind] = validate_artifact_listing(
            kind, page, source_sha=source_sha, run_id=run_id,
        )

    with TemporaryDirectory(prefix="request-guard-qualification-") as temp:
        root = Path(temp)
        native_hashes: dict[str, str] = {}
        for platform in PLATFORMS:
            name = f"request-guard-mcp-{platform}"
            require(name in artifacts["native"], f"missing native artifact: {platform}")
            destination = root / "native" / platform
            download(repository, annotation["release_run_id"], name, destination)
            evidence = verify_native_files(
                destination, platform=platform, label=label, source_sha=source_sha,
                run_id=annotation["release_run_id"],
                run_attempt=annotation["release_run_attempt"],
            )
            native_hashes[platform] = evidence["archive_sha256"]

        npm_dir = root / "npm-inputs"
        download(repository, annotation["npm_run_id"], "private-npm-candidate-inputs", npm_dir)
        npm = verify_npm_files(
            npm_dir, label=label, source_sha=source_sha,
            run_id=annotation["npm_run_id"], run_attempt=annotation["npm_run_attempt"],
            release_run_id=annotation["release_run_id"],
            release_run_attempt=annotation["release_run_attempt"],
        )
        require(npm["tarball_sha256"] == annotation["npm_tarball_sha256"],
                "tag npm tarball digest differs from qualified tarball")
        for platform in PLATFORMS:
            evidence = verify_native_files(
                npm_dir / "assets", platform=platform, label=label, source_sha=source_sha,
                run_id=annotation["release_run_id"],
                run_attempt=annotation["release_run_attempt"],
            )
            require(evidence["archive_sha256"] == native_hashes[platform],
                    f"npm input differs from qualified native archive: {platform}")

        container_inputs: dict[str, dict[str, str]] = {}
        for arch in ("amd64", "arm64"):
            name = f"private-container-inputs-{arch}"
            require(name in artifacts["container"], f"missing container artifact: {arch}")
            destination = root / "container" / arch
            download(repository, annotation["container_run_id"], name, destination)
            evidence = verify_container_files(
                destination, platform=arch, label=label, source_sha=source_sha,
                run_id=annotation["container_run_id"],
                run_attempt=annotation["container_run_attempt"],
            )
            container_inputs[arch] = {
                stage: evidence[f"{stage}_sha256"]
                for stage in ("builder", "runtime", "toolchain")
            }
    return {
        "tag_object_sha": tag_sha,
        "source_sha": source_sha,
        "candidate_label": label,
        "native_archives_sha256": native_hashes,
        "npm_tarball_sha256": npm["tarball_sha256"],
        "container_input_sha256": container_inputs,
        "run_ids": {
            kind: runs[kind]["id"] for kind in ("native", "npm", "container")
        },
    }


def main() -> None:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    label = os.environ.get("GITHUB_REF_NAME", "")
    source_sha = os.environ.get("GITHUB_SHA", "")
    result = qualify(repository=repository, label=label, source_sha=source_sha)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
