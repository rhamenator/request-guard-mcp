#!/usr/bin/env python3
"""Keep future public tags blocked while installer qualification is absent."""

import os
from pathlib import Path
import subprocess
import sys


SCRIPT = Path(__file__).with_name("verify_installer_release_gate.py")


def run(event: str, ref_type: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        env={**os.environ, "GITHUB_EVENT_NAME": event, "GITHUB_REF_TYPE": ref_type},
        text=True,
        capture_output=True,
        check=False,
    )


def main() -> None:
    private = run("workflow_dispatch", "branch")
    assert private.returncode == 0, private.stderr
    assert "not applicable" in private.stdout

    public = run("push", "tag")
    assert public.returncode != 0, public.stdout
    assert "Public tag blocked" in public.stderr
    assert "clean install/uninstall" in public.stderr
    manual_tag = run("workflow_dispatch", "tag")
    assert manual_tag.returncode != 0
    assert "Unexpected release context" in manual_tag.stderr
    print("PASS installer publication gate: private candidate allowed, tag blocked")


if __name__ == "__main__":
    main()
