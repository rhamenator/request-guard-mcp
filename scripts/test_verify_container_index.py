#!/usr/bin/env python3
"""Exercise the index gate before any registry tag is assigned."""

from copy import deepcopy
from pathlib import Path

from verify_container_index import verify_index


def descriptor(arch: str, digit: str) -> dict:
    return {"digest": "sha256:" + digit * 64, "platform": {"os": "linux", "architecture": arch}}


def attestation(digit: str, subject: str) -> dict:
    return {
        "digest": "sha256:" + digit * 64,
        "platform": {"os": "unknown", "architecture": "unknown"},
        "annotations": {
            "vnd.docker.reference.type": "attestation-manifest",
            "vnd.docker.reference.digest": "sha256:" + subject * 64,
        },
    }


valid = {"manifests": [
    descriptor("amd64", "a"), attestation("c", "a"),
    descriptor("arm64", "b"), attestation("d", "b"),
]}
verify_index(valid)

for mutate in (
    lambda x: x["manifests"].pop(),
    lambda x: x["manifests"][2]["platform"].update(architecture="amd64"),
    lambda x: x["manifests"][3]["annotations"].update(
        {"vnd.docker.reference.digest": "sha256:" + "a" * 64}
    ),
    lambda x: x["manifests"].append(descriptor("s390x", "e")),
    lambda x: x["manifests"][0].update(digest="sha256:invalid"),
):
    case = deepcopy(valid)
    mutate(case)
    try:
        verify_index(case)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid index was accepted")

workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/container.yml").read_text()
preflight = workflow.index("imagetools create --dry-run")
publish = workflow.index("imagetools create --metadata-file")
assert preflight < publish
assert workflow.index("verify_container_index.py proposed-index.json") < publish
assert workflow.index("verify_container_index.py published-index.json") > publish

print("PASS container index preflight and five negative controls")
