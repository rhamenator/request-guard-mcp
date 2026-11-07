#!/usr/bin/env python3
"""Negative qualification checks must fail before any tag can publish."""

from copy import deepcopy

from private_candidate_gate import (
    NATIVE_SKIPPED_JOBS, PLATFORMS, REQUIRED_JOBS, WORKFLOWS,
    validate_evidence, validate_run,
)


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
    for kind in WORKFLOWS:
        run, jobs = fixture(kind)
        validate(kind, run, jobs)
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
    print("PASS private candidate gate: exact jobs, source, label and run attempts")


if __name__ == "__main__":
    main()
