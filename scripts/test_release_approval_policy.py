#!/usr/bin/env python3
"""Guard the public v1 tag approval chain without creating a release tag."""

from pathlib import Path
import re


source = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
assert "permissions: write-all" not in source
workflow = source.split("\njobs:\n", 1)[1]
matches = list(re.finditer(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\n", workflow, re.MULTILINE))
jobs = {
    match.group(1): workflow[match.end() : matches[index + 1].start() if index + 1 < len(matches) else len(workflow)]
    for index, match in enumerate(matches)
}
assert set(jobs) == {
    "verify-release-ref",
    "stable-tag-approval",
    "build-release",
    "attest-native-provenance",
    "create-release",
}, "review publication permissions when release jobs change"

approval = jobs["stable-tag-approval"]
build = jobs["build-release"]
attest = jobs["attest-native-provenance"]
publish = jobs["create-release"]

def active_lines(job):
    return [line for line in job.splitlines() if not line.lstrip().startswith("#")]


def job_line(job, value):
    return f"    {value}" in active_lines(job)


assert job_line(approval, "environment: stable-release")
assert job_line(approval, "needs: verify-release-ref")
assert job_line(approval, (
    "if: github.event_name == 'push' && github.ref_type == 'tag' "
    "&& !startsWith(github.ref_name, 'v0.')"
)), "all v1+ tags, including prereleases, must pause for owner approval"
assert job_line(build, "needs: [verify-release-ref, stable-tag-approval]")
assert "        if: github.event_name != 'push' || github.ref_type != 'tag'" in active_lines(build), (
    "tagged native builds must not restore cached Rust build outputs"
)
assert job_line(build, (
    "if: ${{ !cancelled() && needs.verify-release-ref.result == 'success' "
    "&& (needs.stable-tag-approval.result == 'success' || "
    "(needs.stable-tag-approval.result == 'skipped' && "
    "(github.event_name == 'workflow_dispatch' || "
    "(github.event_name == 'push' && github.ref_type == 'tag' "
    "&& startsWith(github.ref_name, 'v0.'))))) }}"
)), "a skipped approval must build only a private dispatch or v0 tag"
assert job_line(attest, "needs: build-release")
assert job_line(attest, (
    "if: ${{ !cancelled() && github.event_name == 'push' "
    "&& github.ref_type == 'tag' && needs.build-release.result == 'success' }}"
))
assert job_line(publish, "needs: [verify-release-ref, build-release, attest-native-provenance]")
assert job_line(publish, "if: github.event_name == 'push' && github.ref_type == 'tag'")
assert "          draft: ${{ !startsWith(github.ref_name, 'v0.') }}" in active_lines(publish), (
    "v1+ native assets must remain in a draft until exact tagged-byte review"
)
assert "environment: stable-release" not in jobs.get("verify-release-ref", "")

for name, job in jobs.items():
    lines = [line.strip() for line in active_lines(job)]
    assert "continue-on-error: true" not in lines, name
    if "contents: write" in lines:
        assert name == "create-release", name
    if "id-token: write" in lines or "attestations: write" in lines:
        assert name == "attest-native-provenance", name

container_source = (Path(__file__).resolve().parents[1] / ".github/workflows/container.yml").read_text()
assert "permissions: write-all" not in container_source
container_workflow = container_source.split("\njobs:\n", 1)[1]
container_matches = list(re.finditer(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\n", container_workflow, re.MULTILINE))
container_jobs = {
    match.group(1): container_workflow[
        match.end() : container_matches[index + 1].start() if index + 1 < len(container_matches) else len(container_workflow)
    ]
    for index, match in enumerate(container_matches)
}
assert set(container_jobs) == {
    "verify-container-ref",
    "stable-tag-approval",
    "build-and-push",
    "build-platform",
    "publish-container",
}, "review GHCR publication permissions when container jobs change"

container_approval = container_jobs["stable-tag-approval"]
platform = container_jobs["build-platform"]
multiarch = container_jobs["publish-container"]
assert job_line(container_approval, "environment: stable-release")
assert job_line(container_approval, "needs: verify-container-ref")
assert job_line(container_approval, (
    "if: ${{ !cancelled() && github.ref_type == 'tag' "
    "&& !startsWith(github.ref_name, 'v0.') "
    "&& needs.verify-container-ref.result == 'success' }}"
)), "every v1+ container tag, including prereleases, must pause for owner approval"
assert job_line(platform, "needs: [verify-container-ref, stable-tag-approval]")
assert job_line(platform, (
    "if: ${{ !cancelled() && github.event_name != 'pull_request' "
    "&& (github.ref_type == 'tag' || github.ref == 'refs/heads/main') "
    "&& needs.verify-container-ref.result == 'success' "
    "&& needs.verify-container-ref.outputs.publish == 'true' "
    "&& (needs.stable-tag-approval.result == 'success' || "
    "(needs.stable-tag-approval.result == 'skipped' && "
    "(github.ref == 'refs/heads/main' || "
    "(github.ref_type == 'tag' && startsWith(github.ref_name, 'v0.'))))) }}"
)), "a skipped approval may publish only main's experimental image or a v0 tag"
assert job_line(multiarch, "needs: build-platform")
assert job_line(multiarch, (
    "if: ${{ !cancelled() && github.event_name != 'pull_request' "
    "&& needs.build-platform.result == 'success' }}"
))
assert "          push: false" in active_lines(container_jobs["build-and-push"])
for name, job in container_jobs.items():
    lines = [line.strip() for line in active_lines(job)]
    assert "continue-on-error: true" not in lines, name
    if "packages: write" in lines:
        assert name in {"build-platform", "publish-container"}, name

print("PASS public v1 native and container tag approval dependency policy")
