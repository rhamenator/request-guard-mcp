"""Pure checks for source-bound unpublished qualification runs.

Network retrieval and publication remain in the fail-closed release guard.
Keeping these checks pure makes missing-platform and wrong-source cases testable.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Callable

from write_private_candidate_evidence import digest, native_fields


PLATFORMS = (
    "linux-x64", "linux-x64-musl", "windows-x64", "macos-x64", "macos-arm64"
)
WORKFLOWS = {
    "native": ".github/workflows/release.yml",
    "npm": ".github/workflows/qualify-private-npm.yml",
    "container": ".github/workflows/qualify-private-container.yml",
}
REQUIRED_JOBS = {
    "native": {"Verify release version and source", *(f"Build {p} binary" for p in PLATFORMS)},
    "npm": {"Verify source and pack private candidate", *(f"private npm install/uninstall ({p})" for p in PLATFORMS)},
    "container": {"Private candidate container (amd64)", "Private candidate container (arm64)"},
}
NATIVE_SKIPPED_JOBS = {
    "Approve v1+ release tag", "Attest and verify tagged native archives", "Create GitHub Release"
}
TAG_EVIDENCE_HEADER = "Request Guard MCP qualification v1"
TAG_EVIDENCE_KEYS = {
    "candidate_label", "source_sha", "release_run", "npm_run", "container_run",
    "npm_tarball_sha256",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_tag_evidence(message: str, *, label: str, source_sha: str) -> dict[str, object]:
    """Parse an annotated tag's owner-reviewed qualification run references."""
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    require(bool(lines) and lines[0] == TAG_EVIDENCE_HEADER,
            "annotated tag lacks Request Guard qualification header")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        require("=" in line, "invalid tag qualification field")
        key, value = line.split("=", 1)
        require(key in TAG_EVIDENCE_KEYS and key not in fields and value == value.strip(),
                "unknown or duplicate tag qualification field")
        fields[key] = value
    require(fields.keys() == TAG_EVIDENCE_KEYS, "tag qualification fields incomplete")
    require(fields["candidate_label"] == label, "tag candidate label mismatch")
    require(fields["source_sha"] == source_sha, "tag source SHA mismatch")
    require(re.fullmatch(r"[0-9a-f]{64}", fields["npm_tarball_sha256"]) is not None,
            "tag npm tarball digest invalid")
    result: dict[str, object] = {
        "candidate_label": label,
        "source_sha": source_sha,
        "npm_tarball_sha256": fields["npm_tarball_sha256"],
    }
    for kind in ("release", "npm", "container"):
        match = re.fullmatch(r"([1-9][0-9]*)/([1-9][0-9]*)", fields[f"{kind}_run"])
        require(match is not None, f"tag {kind} run ID/attempt invalid")
        result[f"{kind}_run_id"] = int(match.group(1))
        result[f"{kind}_run_attempt"] = int(match.group(2))
    return result


def load_annotated_tag(
    *, repository: str, label: str, source_sha: str,
    api: Callable[[str], dict], expected_tag_object_sha: str | None = None,
) -> tuple[str, dict[str, object]]:
    """Resolve the current GitHub tag ref and bind its annotation to the commit.

    Calling this again with the returned object SHA detects tag replacement
    between initial qualification and a publishing step.
    """
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
            "invalid repository")
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?", label) is not None,
            "invalid release tag name")
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None, "invalid source SHA")
    ref = api(f"repos/{repository}/git/ref/tags/{label}")
    require(ref.get("ref") == f"refs/tags/{label}", "tag reference mismatch")
    obj = ref.get("object", {})
    require(obj.get("type") == "tag", "release tag must be annotated")
    tag_sha = obj.get("sha", "")
    require(re.fullmatch(r"[0-9a-f]{40}", str(tag_sha)) is not None,
            "invalid tag object SHA")
    if expected_tag_object_sha is not None:
        require(tag_sha == expected_tag_object_sha, "release tag object changed")
    tag = api(f"repos/{repository}/git/tags/{tag_sha}")
    require(tag.get("sha") == tag_sha and tag.get("tag") == label,
            "annotated tag object mismatch")
    target = tag.get("object", {})
    require(target.get("type") == "commit" and target.get("sha") == source_sha,
            "annotated tag target commit mismatch")
    evidence = parse_tag_evidence(tag.get("message", ""), label=label, source_sha=source_sha)
    return tag_sha, evidence


def validate_run(
    kind: str, run: dict, jobs: list[dict], *, repository: str, source_sha: str,
    run_id: int, run_attempt: int,
) -> None:
    require(kind in WORKFLOWS, "unknown qualification kind")
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None, "invalid source SHA")
    require(isinstance(run_id, int) and run_id > 0, "invalid run ID")
    require(isinstance(run_attempt, int) and run_attempt > 0, "invalid run attempt")
    require(run.get("id") == run_id, f"{kind} run ID mismatch")
    require(run.get("run_attempt") == run_attempt, f"{kind} run attempt mismatch")
    require(run.get("path") == WORKFLOWS[kind], f"{kind} workflow path mismatch")
    require(run.get("event") == "workflow_dispatch", f"{kind} was not private dispatch")
    require(run.get("conclusion") == "success", f"{kind} run did not succeed")
    require(run.get("head_sha") == source_sha, f"{kind} source SHA mismatch")
    require(run.get("head_repository", {}).get("full_name") == repository,
            f"{kind} source repository mismatch")
    require(run.get("repository", {}).get("full_name") == repository,
            f"{kind} workflow repository mismatch")

    names: dict[str, str] = {}
    for job in jobs:
        require(job.get("run_attempt") == run_attempt, f"{kind} mixed job attempts")
        require(job.get("head_sha") == source_sha, f"{kind} job source mismatch")
        name = job.get("name")
        require(isinstance(name, str) and name not in names, f"{kind} duplicate/invalid job name")
        names[name] = job.get("conclusion", "")
    required = REQUIRED_JOBS[kind]
    require(required <= names.keys(), f"{kind} missing jobs: {sorted(required - names.keys())}")
    for name in required:
        require(names[name] == "success", f"{kind} job failed: {name}")
    if kind == "native":
        for name in NATIVE_SKIPPED_JOBS:
            require(names.get(name) == "skipped", f"private native publication job not skipped: {name}")
    allowed = required | (NATIVE_SKIPPED_JOBS if kind == "native" else set())
    require(names.keys() == allowed, f"{kind} unexpected jobs: {sorted(names.keys() - allowed)}")


def fetch_qualification_run(
    kind: str, *, repository: str, source_sha: str, run_id: int,
    run_attempt: int, api: Callable[[str], dict],
) -> tuple[dict, list[dict]]:
    """Fetch one exact Actions attempt and reject truncated job listings."""
    run = api(f"repos/{repository}/actions/runs/{run_id}")
    page = api(
        f"repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}/jobs?per_page=100"
    )
    jobs = page.get("jobs")
    require(isinstance(jobs, list) and page.get("total_count") == len(jobs)
            and len(jobs) <= 100, f"{kind} job list missing or truncated")
    validate_run(kind, run, jobs, repository=repository, source_sha=source_sha,
                 run_id=run_id, run_attempt=run_attempt)
    return run, jobs


def validate_artifact_listing(
    kind: str, page: dict, *, source_sha: str, run_id: int,
) -> dict[str, int]:
    """Select unique, unexpired artifact IDs bound to the exact Actions run."""
    require(kind in WORKFLOWS, "unknown qualification kind")
    artifacts = page.get("artifacts")
    require(isinstance(artifacts, list) and page.get("total_count") == len(artifacts)
            and len(artifacts) <= 100, f"{kind} artifact list missing or truncated")
    names: dict[str, int] = {}
    for artifact in artifacts:
        name = artifact.get("name")
        require(isinstance(name, str) and name not in names,
                f"{kind} duplicate or invalid artifact name")
        require(artifact.get("expired") is False, f"{kind} artifact expired: {name}")
        origin = artifact.get("workflow_run", {})
        require(origin.get("id") == run_id and origin.get("head_sha") == source_sha,
                f"{kind} artifact source/run mismatch: {name}")
        artifact_id = artifact.get("id")
        require(isinstance(artifact_id, int) and artifact_id > 0,
                f"{kind} artifact ID invalid: {name}")
        names[name] = artifact_id
    expected = {
        "native": {f"request-guard-mcp-{platform}" for platform in PLATFORMS},
        "npm": {"private-npm-candidate-inputs"},
        "container": {"private-container-inputs-amd64", "private-container-inputs-arm64"},
    }[kind]
    require(expected <= names.keys(), f"{kind} missing artifacts: {sorted(expected - names.keys())}")
    return {name: names[name] for name in expected}


def verify_native_files(
    directory: Path, *, platform: str, label: str, source_sha: str,
    run_id: int, run_attempt: int,
) -> dict:
    """Verify downloaded native archive, SHA sidecar, and bound evidence."""
    require(platform in PLATFORMS, "unknown native platform")
    extension = "zip" if platform == "windows-x64" else "tar.gz"
    archive = directory / f"request-guard-mcp-{label}-{platform}.{extension}"
    sidecar = directory / f"{archive.name}.sha256"
    evidence_path = directory / f"private-evidence-{platform}.json"
    evidence = json.loads(evidence_path.read_text())
    validate_evidence("native", evidence, label=label, source_sha=source_sha,
                      run_id=run_id, run_attempt=run_attempt, platform=platform)
    require(native_fields(archive, sidecar)["archive_sha256"] == evidence["archive_sha256"],
            "native archive digest differs from qualification evidence")
    return evidence


def verify_npm_files(
    directory: Path, *, label: str, source_sha: str, run_id: int,
    run_attempt: int, release_run_id: int, release_run_attempt: int,
) -> dict:
    """Verify the candidate tarball bound to the native Release run."""
    evidence = json.loads((directory / "npm/private-evidence.json").read_text())
    validate_evidence("npm", evidence, label=label, source_sha=source_sha,
                      run_id=run_id, run_attempt=run_attempt,
                      release_run_id=release_run_id,
                      release_run_attempt=release_run_attempt)
    tarball = directory / "npm" / evidence["tarball"]
    require(digest(tarball) == evidence["tarball_sha256"], "npm tarball digest mismatch")
    return evidence


def verify_container_files(
    directory: Path, *, platform: str, label: str, source_sha: str,
    run_id: int, run_attempt: int,
) -> dict:
    """Verify recorded input inventories for an unpublished local image."""
    evidence = json.loads((directory / "private-evidence.json").read_text())
    validate_evidence("container", evidence, label=label, source_sha=source_sha,
                      run_id=run_id, run_attempt=run_attempt, platform=platform)
    for stage in ("builder", "runtime", "toolchain"):
        require(digest(directory / f"{stage}.txt") == evidence[f"{stage}_sha256"],
                f"container {stage} inventory digest mismatch")
    return evidence


def validate_evidence(
    kind: str, evidence: dict, *, label: str, source_sha: str, run_id: int,
    run_attempt: int, platform: str | None = None, release_run_id: int | None = None,
    release_run_attempt: int | None = None,
) -> None:
    require(evidence.get("schema") == 1, f"{kind} evidence schema mismatch")
    require(evidence.get("kind") == kind, f"{kind} evidence kind mismatch")
    require(evidence.get("candidate_label") == label, f"{kind} candidate label mismatch")
    require(evidence.get("source_sha") == source_sha, f"{kind} evidence source mismatch")
    require(evidence.get("run_id") == run_id, f"{kind} evidence run ID mismatch")
    require(evidence.get("run_attempt") == run_attempt, f"{kind} evidence attempt mismatch")
    if platform is not None:
        require(evidence.get("platform") == platform, f"{kind} platform mismatch")
    if kind == "npm":
        require(evidence.get("release_run_id") == release_run_id,
                "npm evidence Release run mismatch")
        require(evidence.get("release_run_attempt") == release_run_attempt,
                "npm evidence Release attempt mismatch")
        require(re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("tarball_sha256", ""))) is not None,
                "npm tarball digest missing")
        require(evidence.get("tarball") == f"request-guard-mcp-{label.removeprefix('v')}.tgz",
                "npm tarball label mismatch")
    elif kind == "native":
        require(re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("archive_sha256", ""))) is not None,
                "native archive digest missing")
        extension = "zip" if platform == "windows-x64" else "tar.gz"
        require(evidence.get("archive") == f"request-guard-mcp-{label}-{platform}.{extension}",
                "native archive label/platform mismatch")
    elif kind == "container":
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", str(evidence.get("image_id", ""))) is not None,
                "private image ID missing")
        for stage in ("builder", "runtime", "toolchain"):
            require(re.fullmatch(r"[0-9a-f]{64}", str(evidence.get(f"{stage}_sha256", "")))
                    is not None, f"container {stage} digest missing")
