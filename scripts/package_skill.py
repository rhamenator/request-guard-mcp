#!/usr/bin/env python3
"""Build a minimal, deterministic ZIP for the companion Request Guard skill."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "request-guard-mcp" / "SKILL.md"
ARCHIVE_NAME = "request-guard-mcp/SKILL.md"


def validate_skill(data: bytes) -> None:
    text = data.decode("utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("SKILL.md must start with YAML frontmatter")
    try:
        closing = lines.index("---", 1)
    except ValueError as error:
        raise ValueError("SKILL.md needs a standalone closing frontmatter delimiter") from error
    frontmatter = lines[1:closing]
    body = "\n".join(lines[closing + 1 :])
    fields = dict(
        match.groups()
        for line in frontmatter
        if (match := re.fullmatch(r"(name|description):\s*(.+)", line))
    )
    if fields.get("name") != "request-guard-mcp":
        raise ValueError("SKILL.md must declare name: request-guard-mcp")
    if not fields.get("description", "").strip() or not body.strip():
        raise ValueError("SKILL.md needs a description and instructions")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "request-guard-mcp-skill.zip",
    )
    args = parser.parse_args()
    if SKILL.is_symlink() or not SKILL.is_file():
        parser.error("skill entrypoint must be a regular file")
    data = SKILL.read_bytes()
    validate_skill(data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    entry = ZipInfo(ARCHIVE_NAME, (1980, 1, 1, 0, 0, 0))
    entry.create_system = 3
    entry.compress_type = ZIP_DEFLATED
    entry.external_attr = 0o644 << 16
    with ZipFile(args.output, "w") as archive:
        archive.writestr(entry, data)
    with ZipFile(args.output) as archive:
        if archive.namelist() != [ARCHIVE_NAME] or archive.read(ARCHIVE_NAME) != data:
            raise ValueError("packaged skill verification failed")
    print(args.output)


if __name__ == "__main__":
    main()
