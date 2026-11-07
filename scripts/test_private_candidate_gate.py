#!/usr/bin/env python3
"""Negative qualification checks must fail before any tag can publish."""

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from private_candidate_gate import (
    NATIVE_SKIPPED_JOBS, PLATFORMS, REQUIRED_JOBS, WORKFLOWS,
    fetch_qualification_run, load_annotated_tag, parse_tag_evidence,
    validate_artifact_listing, validate_evidence, validate_run,
    verify_container_files, verify_native_files, verify_npm_files,
)
from write_private_candidate_evidence import digest


SOURCE = "a" * 40
REPO = "owner/request-guard-mcp"
LABEL = "v1.1.0-rc.2"


def rejects(function, *args, contains: str, **kwargs) -> None:
    try:
        function(*args, **kwargs)
    except ValueError as error:
        assert contains in str(error), error
    else:
        raise AssertionError(f"expected rejection containing {contains!r}")


def fixture(kind: str):
    run = {
        "id": 123, "run_attempt": 2, "path": WORKFLOWS[kind],
        "event": "workflow_dispatch", "conclusion": "success", "head_sha": SOURCE,
        "head_repository": {"full_name": REPO}, "repository": {"full_name": REPO},
    }
    names = REQUIRED_JOBS[kind]
    jobs = [
        {"name": name, "conclusion": "success", "head_sha": SOURCE, "run_attempt": 2}
        for name in sorted(names)
    ]
    if kind == "native":
        jobs += [
            {"name": name, "conclusion": "skipped", "head_sha": SOURCE, "run_attempt": 2}
            for name in sorted(NATIVE_SKIPPED_JOBS)
        ]
    return run, jobs


def validate(kind: str, run: dict, jobs: list[dict]) -> None:
    validate_run(kind, run, jobs, repository=REPO, source_sha=SOURCE,
                 run_id=123, run_attempt=2)


def main() -> None:
    tag_message = (
        "Request Guard MCP qualification v1\n"
        f"candidate_label={LABEL}\nsource_sha={SOURCE}\n"
        "release_run=123/2\nnpm_run=456/1\ncontainer_run=789/3\n"
        f"npm_tarball_sha256={'d' * 64}\n"
    )
    tag = parse_tag_evidence(tag_message, label=LABEL, source_sha=SOURCE)
    assert (tag["release_run_id"], tag["release_run_attempt"]) == (123, 2)
    assert (tag["npm_run_id"], tag["container_run_attempt"]) == (456, 3)
    rejects(parse_tag_evidence, tag_message.replace(LABEL, "v1.1.0-rc.1"),
            label=LABEL, source_sha=SOURCE, contains="candidate label mismatch")
    rejects(parse_tag_evidence, tag_message.replace(SOURCE, "b" * 40),
            label=LABEL, source_sha=SOURCE, contains="source SHA mismatch")
    rejects(parse_tag_evidence, tag_message.replace("d" * 64, "invalid"),
            label=LABEL, source_sha=SOURCE, contains="tarball digest invalid")
    rejects(parse_tag_evidence, tag_message.replace("release_run=123/2", "release_run=0/2"),
            label=LABEL, source_sha=SOURCE, contains="run ID/attempt invalid")
    rejects(parse_tag_evidence, tag_message + "release_run=123/2\n",
            label=LABEL, source_sha=SOURCE, contains="duplicate")
    rejects(parse_tag_evidence, tag_message.replace("container_run=789/3\n", ""),
            label=LABEL, source_sha=SOURCE, contains="fields incomplete")

    tag_sha = "1" * 40
    ref_path = f"repos/{REPO}/git/ref/tags/{LABEL}"
    object_path = f"repos/{REPO}/git/tags/{tag_sha}"
    responses = {
        ref_path: {"ref": f"refs/tags/{LABEL}", "object": {"type": "tag", "sha": tag_sha}},
        object_path: {"sha": tag_sha, "tag": LABEL,
                      "object": {"type": "commit", "sha": SOURCE}, "message": tag_message},
    }
    api = responses.__getitem__
    resolved_sha, resolved = load_annotated_tag(
        repository=REPO, label=LABEL, source_sha=SOURCE, api=api)
    assert resolved_sha == tag_sha and resolved == tag
    rejects(load_annotated_tag, repository=REPO, label=LABEL, source_sha=SOURCE,
            api=api, expected_tag_object_sha="2" * 40, contains="tag object changed")
    original_ref = responses[ref_path]
    responses[ref_path] = {"ref": f"refs/tags/{LABEL}",
                           "object": {"type": "commit", "sha": SOURCE}}
    rejects(load_annotated_tag, repository=REPO, label=LABEL, source_sha=SOURCE,
            api=api, contains="must be annotated")
    responses[ref_path] = original_ref
    original_object = responses[object_path]
    responses[object_path] = dict(original_object, object={"type": "commit", "sha": "b" * 40})
    rejects(load_annotated_tag, repository=REPO, label=LABEL, source_sha=SOURCE,
            api=api, contains="target commit mismatch")
    responses[object_path] = original_object

    for kind in WORKFLOWS:
        run, jobs = fixture(kind)
        validate(kind, run, jobs)
        run_path = f"repos/{REPO}/actions/runs/123"
        jobs_path = f"{run_path}/attempts/2/jobs?per_page=100"
        responses = {run_path: run, jobs_path: {"total_count": len(jobs), "jobs": jobs}}
        fetched_run, fetched_jobs = fetch_qualification_run(
            kind, repository=REPO, source_sha=SOURCE, run_id=123,
            run_attempt=2, api=responses.__getitem__)
        assert fetched_run == run and fetched_jobs == jobs
        responses[jobs_path] = {"total_count": len(jobs) + 1, "jobs": jobs}
        rejects(fetch_qualification_run, kind, repository=REPO, source_sha=SOURCE,
                run_id=123, run_attempt=2, api=responses.__getitem__,
                contains="job list missing or truncated")
        extra = jobs + [{"name": "Unreviewed publish", "conclusion": "success",
                         "head_sha": SOURCE, "run_attempt": 2}]
        rejects(validate, kind, run, extra, contains="unexpected jobs")

        bad = deepcopy(run)
        bad["head_sha"] = "b" * 40
        rejects(validate, kind, bad, jobs, contains="source SHA mismatch")
        bad = deepcopy(run)
        bad["path"] = ".github/workflows/untrusted.yml"
        rejects(validate, kind, bad, jobs, contains="workflow path mismatch")
        bad = deepcopy(run)
        bad["run_attempt"] = 3
        rejects(validate, kind, bad, jobs, contains="run attempt mismatch")
        rejects(validate, kind, run, jobs[:-1], contains="missing jobs" if kind != "native" else "not skipped")

    run, jobs = fixture("native")
    jobs = [job for job in jobs if job["name"] != "Build macos-arm64 binary"]
    rejects(validate, "native", run, jobs, contains="missing jobs")

    run, jobs = fixture("npm")
    jobs = [job for job in jobs if job["name"] != f"private npm install/uninstall ({PLATFORMS[0]})"]
    rejects(validate, "npm", run, jobs, contains="missing jobs")

    native = {
        "schema": 1, "kind": "native", "candidate_label": LABEL,
        "source_sha": SOURCE, "run_id": 123, "run_attempt": 2,
        "platform": "linux-x64", "archive_sha256": "c" * 64,
        "archive": "request-guard-mcp-v1.1.0-rc.2-linux-x64.tar.gz",
    }
    validate_evidence("native", native, label=LABEL, source_sha=SOURCE,
                      run_id=123, run_attempt=2, platform="linux-x64")
    bad = dict(native, candidate_label="v1.1.0-rc.1")
    rejects(validate_evidence, "native", bad, label=LABEL, source_sha=SOURCE,
            run_id=123, run_attempt=2, platform="linux-x64", contains="candidate label mismatch")

    npm = {
        "schema": 1, "kind": "npm", "candidate_label": LABEL,
        "source_sha": SOURCE, "run_id": 456, "run_attempt": 1,
        "release_run_id": 123, "release_run_attempt": 2, "tarball_sha256": "d" * 64,
        "tarball": "request-guard-mcp-1.1.0-rc.2.tgz",
    }
    validate_evidence("npm", npm, label=LABEL, source_sha=SOURCE, run_id=456,
                      run_attempt=1, release_run_id=123, release_run_attempt=2)
    rejects(validate_evidence, "npm", dict(npm, release_run_id=999), label=LABEL,
            source_sha=SOURCE, run_id=456, run_attempt=1,
            release_run_id=123, release_run_attempt=2, contains="Release run mismatch")

    container = {
        "schema": 1, "kind": "container", "candidate_label": LABEL,
        "source_sha": SOURCE, "run_id": 789, "run_attempt": 3,
        "platform": "amd64", "image_id": "sha256:" + "e" * 64,
        **{f"{stage}_sha256": "f" * 64 for stage in ("builder", "runtime", "toolchain")},
    }
    validate_evidence("container", container, label=LABEL, source_sha=SOURCE,
                      run_id=789, run_attempt=3, platform="amd64")
    rejects(validate_evidence, "container", dict(container, platform="arm64"),
            label=LABEL, source_sha=SOURCE, run_id=789, run_attempt=3,
            platform="amd64", contains="platform mismatch")

    artifact_names = [f"request-guard-mcp-{platform}" for platform in PLATFORMS]
    artifact_page = {"total_count": 5, "artifacts": [
        {"id": number, "name": name, "expired": False,
         "workflow_run": {"id": 123, "head_sha": SOURCE}}
        for number, name in enumerate(artifact_names, 1)
    ]}
    selected = validate_artifact_listing("native", artifact_page, source_sha=SOURCE, run_id=123)
    assert set(selected) == set(artifact_names)
    missing = deepcopy(artifact_page)
    missing["artifacts"].pop()
    missing["total_count"] = 4
    rejects(validate_artifact_listing, "native", missing, source_sha=SOURCE,
            run_id=123, contains="missing artifacts")
    expired = deepcopy(artifact_page)
    expired["artifacts"][0]["expired"] = True
    rejects(validate_artifact_listing, "native", expired, source_sha=SOURCE,
            run_id=123, contains="artifact expired")
    wrong_source = deepcopy(artifact_page)
    wrong_source["artifacts"][0]["workflow_run"]["head_sha"] = "b" * 40
    rejects(validate_artifact_listing, "native", wrong_source, source_sha=SOURCE,
            run_id=123, contains="artifact source/run mismatch")
    duplicate = deepcopy(artifact_page)
    duplicate["artifacts"].append(dict(duplicate["artifacts"][0], id=99))
    duplicate["total_count"] = 6
    rejects(validate_artifact_listing, "native", duplicate, source_sha=SOURCE,
            run_id=123, contains="duplicate")

    with TemporaryDirectory() as directory:
        root = Path(directory)
        archive = root / native["archive"]
        archive.write_bytes(b"native bytes")
        archive_hash = digest(archive)
        (root / f"{archive.name}.sha256").write_text(f"{archive_hash} *{archive.name}\n")
        native["archive_sha256"] = archive_hash
        (root / "private-evidence-linux-x64.json").write_text(json.dumps(native))
        verify_native_files(root, platform="linux-x64", label=LABEL,
                            source_sha=SOURCE, run_id=123, run_attempt=2)
        archive.write_bytes(b"tampered")
        rejects(verify_native_files, root, platform="linux-x64", label=LABEL,
                source_sha=SOURCE, run_id=123, run_attempt=2, contains="disagree")

        npm_dir = root / "npm"
        npm_dir.mkdir()
        tarball = npm_dir / npm["tarball"]
        tarball.write_bytes(b"candidate tarball")
        npm["tarball_sha256"] = digest(tarball)
        (npm_dir / "private-evidence.json").write_text(json.dumps(npm))
        verify_npm_files(root, label=LABEL, source_sha=SOURCE, run_id=456,
                         run_attempt=1, release_run_id=123, release_run_attempt=2)
        tarball.write_bytes(b"tampered")
        rejects(verify_npm_files, root, label=LABEL, source_sha=SOURCE, run_id=456,
                run_attempt=1, release_run_id=123, release_run_attempt=2,
                contains="tarball digest mismatch")

        for stage in ("builder", "runtime", "toolchain"):
            path = root / f"{stage}.txt"
            path.write_text(stage)
            container[f"{stage}_sha256"] = digest(path)
        (root / "private-evidence.json").write_text(json.dumps(container))
        verify_container_files(root, platform="amd64", label=LABEL,
                               source_sha=SOURCE, run_id=789, run_attempt=3)
        (root / "runtime.txt").write_text("tampered")
        rejects(verify_container_files, root, platform="amd64", label=LABEL,
                source_sha=SOURCE, run_id=789, run_attempt=3,
                contains="runtime inventory digest mismatch")
    print("PASS private candidate gate: exact jobs, source, label and run attempts")


if __name__ == "__main__":
    main()
