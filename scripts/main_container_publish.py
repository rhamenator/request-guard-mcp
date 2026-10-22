#!/usr/bin/env python3
"""Decide whether an untagged main image may be published.

Stable-version images are published from approved tags, not from a main push.
Print a GitHub Actions step output assignment for the container workflow.
"""

import argparse
from pathlib import Path
import re
import tomllib


def publish_main_image(manifest: Path) -> bool:
    version = tomllib.loads(manifest.read_text())["package"]["version"]
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?", version)
    if match is None:
        raise ValueError(f"unsupported Cargo version: {version!r}")
    return int(match.group(1)) == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    args = parser.parse_args()
    print(f"publish={'true' if publish_main_image(args.manifest) else 'false'}")
