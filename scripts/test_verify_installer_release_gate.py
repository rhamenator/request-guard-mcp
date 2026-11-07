#!/usr/bin/env python3
"""Require source-bound qualification and reject unqualified public tags."""

import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from verify_installer_release_gate import main as gate_main


SCRIPT = Path(__file__).with_name("verify_installer_release_gate.py")


def run(event: str, ref_type: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        env={**{k: v for k, v in os.environ.items() if k != "GH_TOKEN"},
             "GITHUB_EVENT_NAME": event, "GITHUB_REF_TYPE": ref_type,
             "GITHUB_REPOSITORY": "owner/request-guard-mcp",
             "GITHUB_REF_NAME": "v1.1.0-rc.2", "GITHUB_SHA": "a" * 40},
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
    assert "GH_TOKEN is required" in public.stderr
    with patch.dict(os.environ, {
        "GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "tag",
        "GITHUB_REPOSITORY": "owner/request-guard-mcp",
        "GITHUB_REF_NAME": "v1.1.0-rc.2", "GITHUB_SHA": "a" * 40,
    }):
        calls = []
        def qualified(**kwargs):
            calls.append(kwargs)
            return {
                "native_archives_sha256": {
                    name: "b" * 64 for name in (
                        "linux-x64", "linux-x64-musl", "windows-x64",
                        "macos-x64", "macos-arm64")
                },
                "container_input_sha256": {"amd64": {}, "arm64": {}},
            }
        gate_main(qualified)
        assert calls == [{
            "repository": "owner/request-guard-mcp", "label": "v1.1.0-rc.2",
            "source_sha": "a" * 40,
        }]
        try:
            gate_main(lambda **_: {"native_archives_sha256": {}, "container_input_sha256": {}})
        except SystemExit as error:
            assert "incomplete" in str(error)
        else:
            raise AssertionError("incomplete qualification accepted")
    manual_tag = run("workflow_dispatch", "tag")
    assert manual_tag.returncode != 0
    assert "Unexpected release context" in manual_tag.stderr
    print("PASS installer publication gate: private candidate allowed, unqualified tag blocked")


if __name__ == "__main__":
    main()
