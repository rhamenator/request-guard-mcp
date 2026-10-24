#!/usr/bin/env python3
"""Require the expected native platforms and their BuildKit attestations."""

import argparse
import json
from pathlib import Path
import re


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def verify_index(index: dict) -> None:
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError("container index has no manifests")

    platforms = {}
    attestations = []
    for manifest in manifests:
        if not isinstance(manifest, dict):
            raise ValueError("container index has an invalid descriptor")
        digest = manifest.get("digest")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError("container index has an invalid digest")
        platform = manifest.get("platform") or {}
        if platform.get("os") == "linux":
            arch = platform.get("architecture")
            if arch in platforms:
                raise ValueError(f"duplicate linux platform: {arch}")
            platforms[arch] = digest
        elif (manifest.get("annotations") or {}).get(
            "vnd.docker.reference.type"
        ) == "attestation-manifest":
            attestations.append(
                (manifest["annotations"].get("vnd.docker.reference.digest"), digest)
            )
        else:
            raise ValueError("unexpected container index descriptor")

    if set(platforms) != {"amd64", "arm64"}:
        raise ValueError(f"container index platforms must be amd64 and arm64: {sorted(platforms)}")
    expected = set(platforms.values())
    referenced = [reference for reference, _ in attestations]
    if len(attestations) != 2 or set(referenced) != expected or len(set(referenced)) != 2:
        raise ValueError("container index needs one attestation per native platform")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path)
    args = parser.parse_args()
    verify_index(json.loads(args.index.read_text()))
    print("Verified amd64/arm64 index and matching attestations")


if __name__ == "__main__":
    main()
