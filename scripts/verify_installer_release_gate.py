#!/usr/bin/env python3
"""Require exact private installer and artifact qualification before a public tag."""

import os

from verify_private_candidate_qualification import qualify


def main(qualifier=qualify) -> None:
    event = os.environ.get("GITHUB_EVENT_NAME")
    ref_type = os.environ.get("GITHUB_REF_TYPE")
    if event == "workflow_dispatch" and ref_type != "tag":
        print("Unpublished candidate: public installer gate is not applicable")
        return
    if event != "push" or ref_type != "tag":
        raise SystemExit(f"Unexpected release context: {event=} {ref_type=}")
    result = qualifier(
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
        label=os.environ.get("GITHUB_REF_NAME", ""),
        source_sha=os.environ.get("GITHUB_SHA", ""),
    )
    if set(result["native_archives_sha256"]) != {
        "linux-x64", "linux-x64-musl", "windows-x64", "macos-x64", "macos-arm64"
    } or set(result["container_input_sha256"]) != {"amd64", "arm64"}:
        raise SystemExit("Public tag blocked: qualified platform matrix is incomplete")
    print("Public tag private qualification passed; owner approval and tagged gates remain required")


if __name__ == "__main__":
    main()
