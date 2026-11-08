#!/usr/bin/env python3
"""Write small source-bound metadata alongside unpublished candidate artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
LABEL = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*\Z")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def native_fields(archive: Path, sidecar: Path) -> dict[str, str]:
    words = sidecar.read_text().strip().split(maxsplit=1)
    if len(words) != 2 or not SHA256.fullmatch(words[0]):
        raise ValueError("invalid native SHA-256 sidecar")
    if words[1].lstrip("*") != archive.name or words[0] != digest(archive):
        raise ValueError("native archive and sidecar disagree")
    return {"archive": archive.name, "archive_sha256": words[0]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("native", "npm", "container"), required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--sidecar", type=Path)
    parser.add_argument("--tarball", type=Path)
    parser.add_argument("--release-run-id")
    parser.add_argument("--release-run-attempt")
    parser.add_argument("--image-id")
    parser.add_argument("--builder", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--toolchain", type=Path)
    args = parser.parse_args()

    source_sha = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not LABEL.fullmatch(args.label) or not SHA1.fullmatch(source_sha):
        parser.error("invalid candidate label or source SHA")
    if not run_id.isdecimal() or not run_attempt.isdecimal() or int(run_id) < 1 or int(run_attempt) < 1:
        parser.error("missing GitHub run identity")

    evidence: dict[str, object] = {
        "schema": 1,
        "kind": args.kind,
        "candidate_label": args.label,
        "source_sha": source_sha,
        "run_id": int(run_id),
        "run_attempt": int(run_attempt),
    }
    if args.kind == "native":
        if args.platform not in {
            "linux-x64", "linux-x64-musl", "windows-x64", "macos-x64", "macos-arm64"
        } or not args.archive or not args.sidecar:
            parser.error("native evidence needs a supported platform, archive and sidecar")
        evidence.update(platform=args.platform, **native_fields(args.archive, args.sidecar))
    elif args.kind == "npm":
        if not args.tarball or not (args.release_run_id or "").isdecimal() or not (
            args.release_run_attempt or ""
        ).isdecimal() or int(args.release_run_id) < 1 or int(args.release_run_attempt) < 1:
            parser.error("npm evidence needs a tarball and source Release run identity")
        evidence.update(
            tarball=args.tarball.name,
            tarball_sha256=digest(args.tarball),
            release_run_id=int(args.release_run_id),
            release_run_attempt=int(args.release_run_attempt),
        )
    else:
        if args.platform not in {"amd64", "arm64"} or not args.image_id or not args.image_id.startswith(
            "sha256:"
        ) or not SHA256.fullmatch(
            args.image_id.removeprefix("sha256:")
        ) or not all((args.builder, args.runtime, args.toolchain)):
            parser.error("container evidence needs an architecture, image ID and inventories")
        evidence.update(
            platform=args.platform,
            image_id=args.image_id,
            builder_sha256=digest(args.builder),
            runtime_sha256=digest(args.runtime),
            toolchain_sha256=digest(args.toolchain),
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
