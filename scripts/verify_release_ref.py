#!/usr/bin/env python3
"""Reject release tags that disagree with Cargo or do not come from main."""

import os
from pathlib import Path
import re
import subprocess
import tomllib


def fail(message):
    raise SystemExit(message)


def main():
    version = tomllib.loads(Path("Cargo.toml").read_text())["package"]["version"]
    packages = tomllib.loads(Path("Cargo.lock").read_text())["package"]
    locked = [p["version"] for p in packages if p["name"] == "request-guard-mcp"]
    if locked != [version]:
        fail(f"Cargo.lock package version {locked} does not match Cargo.toml {version}")

    name = os.environ.get("GITHUB_REF_NAME", "")
    kind = os.environ.get("GITHUB_REF_TYPE", "")
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    candidate = os.environ.get("INPUT_CANDIDATE_VERSION", "")
    if event == "workflow_dispatch":
        if not re.fullmatch(rf"v{re.escape(version)}-[A-Za-z0-9][A-Za-z0-9.-]*", candidate):
            fail(f"private candidate label must be v{version}-<suffix>")
        print(f"Private candidate {candidate} matches package {version}")
        return
    # Keep public tag/version identity unambiguous. The workflow approval
    # predicate pauses every v1+ tag, including prereleases, but build
    # metadata is still unsupported by the artifact naming contract.
    if "+" in name or "+" in version:
        fail("release tags with SemVer build metadata are not supported")
    if kind != "tag" or name != f"v{version}":
        fail(f"release tag must be v{version}; got {name!r} ({kind})")
    subprocess.run(["git", "fetch", "origin", "main", "--no-tags"], check=True)
    sha = os.environ.get("GITHUB_SHA", "")
    if not sha:
        fail("GITHUB_SHA is missing")
    ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", sha, "origin/main"])
    if ancestor.returncode != 0:
        fail("release tag commit is not on main")
    print(f"Release tag {name} matches package and is on main")


if __name__ == "__main__":
    main()
