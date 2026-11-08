#!/usr/bin/env python3
"""Compare tagged container build inventories with qualified private inputs."""

import hashlib
import json
from pathlib import Path
import sys


def verify(qualification: dict, root: Path) -> None:
    expected = qualification["container_input_sha256"]
    if set(expected) != {"amd64", "arm64"}:
        raise ValueError("qualified container architectures are incomplete")
    for arch in ("amd64", "arm64"):
        if set(expected[arch]) != {"builder", "runtime", "toolchain"}:
            raise ValueError(f"qualified container stages are incomplete: {arch}")
        for stage in ("builder", "runtime", "toolchain"):
            path = root / arch / f"{stage}.txt"
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected[arch][stage]:
                raise ValueError(f"tagged container input differs from private candidate: {arch}/{stage}")


if __name__ == "__main__":
    verify(json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2]))
