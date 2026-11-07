#!/usr/bin/env python3
"""Exercise public final/rc refs and private branch dispatch without network I/O."""

from contextlib import chdir, redirect_stdout
from io import StringIO
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

import verify_release_ref


def run_case(event, kind, name, candidate="", sha="a" * 40, ancestor=True):
    with tempfile.TemporaryDirectory() as directory, chdir(directory):
        Path("Cargo.toml").write_text('[package]\nname = "request-guard-mcp"\nversion = "1.1.0"\n')
        Path("Cargo.lock").write_text('[[package]]\nname = "request-guard-mcp"\nversion = "1.1.0"\n')
        env = {
            "GITHUB_EVENT_NAME": event,
            "GITHUB_REF_TYPE": kind,
            "GITHUB_REF_NAME": name,
            "INPUT_CANDIDATE_VERSION": candidate,
            "GITHUB_SHA": sha,
        }
        calls = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            code = 0 if command[1] == "fetch" or ancestor else 1
            return subprocess.CompletedProcess(command, code)

        output = StringIO()
        with patch.dict(os.environ, env), patch.object(verify_release_ref.subprocess, "run", fake_run):
            try:
                with redirect_stdout(output):
                    verify_release_ref.main()
            except SystemExit as error:
                return str(error), calls
        return "", calls


def main():
    error, calls = run_case("workflow_dispatch", "branch", "codex/candidate", "v1.1.0-rc.2")
    assert not error and not calls

    for name in ("v1.1.0", "v1.1.0-rc.2"):
        error, calls = run_case("push", "tag", name)
        assert not error and [call[1] for call in calls] == ["fetch", "merge-base"]

    for name in ("v1.1.0-rc.0", "v1.1.0-rc.02", "v1.1.0-rc.2+meta", "v1.2.0"):
        error, calls = run_case("push", "tag", name)
        assert "release tag must be" in error or "build metadata" in error
        assert not calls

    error, calls = run_case("push", "tag", "v1.1.0-rc.2", ancestor=False)
    assert error == "release tag commit is not on main" and len(calls) == 2

    # A manual dispatch on a tag must follow the public tag path, not the
    # unpublished branch path, even if candidate_version is supplied.
    error, calls = run_case("workflow_dispatch", "tag", "v1.2.0", "v1.1.0-rc.2")
    assert "candidate label must equal" in error and not calls
    error, calls = run_case("workflow_dispatch", "tag", "v1.1.0-rc.2", "v1.1.0-rc.2")
    assert not error and [call[1] for call in calls] == ["fetch", "merge-base"]
    print("PASS release ref: private branch, final/rc tags, ancestry and tag dispatch")


if __name__ == "__main__":
    main()
