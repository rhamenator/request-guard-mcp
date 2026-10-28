#!/usr/bin/env python3
"""Fail closed on public tags until installer qualification is implemented."""

import os


def main() -> None:
    event = os.environ.get("GITHUB_EVENT_NAME")
    ref_type = os.environ.get("GITHUB_REF_TYPE")
    if event == "workflow_dispatch" and ref_type != "tag":
        print("Unpublished candidate: public installer gate is not applicable")
        return
    if event != "push" or ref_type != "tag":
        raise SystemExit(f"Unexpected release context: {event=} {ref_type=}")
    raise SystemExit(
        "Public tag blocked: the all-platform installer build, clean install/"
        "uninstall qualification, and exact-artifact evidence required by "
        "docs/release-policy-2026-10-27.md are not implemented. "
        "Use an unpublished workflow_dispatch candidate until that gate is "
        "implemented, reviewed, and passed."
    )


if __name__ == "__main__":
    main()
