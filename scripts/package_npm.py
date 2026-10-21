#!/usr/bin/env python3
"""Build a dependency-free npm package from verified native release archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path

PLATFORMS = {
    "linux-x64": ("tar.gz", "request-guard-mcp"),
    "linux-x64-musl": ("tar.gz", "request-guard-mcp"),
    "macos-x64": ("tar.gz", "request-guard-mcp"),
    "macos-arm64": ("tar.gz", "request-guard-mcp"),
    "windows-x64": ("zip", "request-guard-mcp.exe"),
}
PACKAGE_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z")
def verify_archive(archive: Path) -> None:
    sidecar = archive.with_name(f"{archive.name}.sha256")
    expected_line = sidecar.read_text(encoding="ascii").strip()
    match = re.fullmatch(r"([0-9a-f]{64}) \*([A-Za-z0-9.+_-]+)", expected_line)
    if not match or match.group(2) != archive.name:
        raise ValueError(f"invalid checksum sidecar: {sidecar}")
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != match.group(1):
        raise ValueError(f"checksum mismatch: {archive}")


def extract_binary(archive: Path, member_name: str, output: Path) -> None:
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as package:
            member = package.getinfo(member_name)
            if stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError(f"binary is a symlink: {member_name}")
            with package.open(member) as source, output.open("wb") as destination:
                shutil.copyfileobj(source, destination)
    else:
        with tarfile.open(archive, "r:gz") as package:
            member = package.getmember(member_name)
            if not member.isfile():
                raise ValueError(f"binary is not a regular file: {member_name}")
            source = package.extractfile(member)
            if source is None:
                raise ValueError(f"binary cannot be read: {member_name}")
            with source, output.open("wb") as destination:
                shutil.copyfileobj(source, destination)
    output.chmod(0o755)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, help="existing npm package name")
    parser.add_argument("--version", required=True, help="release version, with or without v")
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    version = args.version.removeprefix("v")
    if not PACKAGE_NAME.fullmatch(args.name):
        parser.error("invalid npm package name")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        parser.error("version must be npm-compatible semver")
    supports_stdio = tuple(map(int, version.split("-", 1)[0].split("."))) >= (0, 1, 5)
    if args.output.exists():
        parser.error("output directory already exists")

    # Check every input before creating output so a partial package is never mistaken for ready.
    archives = {}
    for platform, (extension, _) in PLATFORMS.items():
        archive = args.assets / f"request-guard-mcp-v{version}-{platform}.{extension}"
        verify_archive(archive)
        archives[platform] = archive

    args.output.mkdir(parents=True)
    (args.output / "bin").mkdir()
    shutil.copy2(Path(__file__).resolve().parents[1] / "npm/bin/request-guard-mcp.js", args.output / "bin/request-guard-mcp.js")
    (args.output / "bin/request-guard-mcp.js").chmod(0o755)
    for platform, (_, binary_name) in PLATFORMS.items():
        target = args.output / "vendor" / platform
        target.mkdir(parents=True)
        prefix = f"request-guard-mcp-v{version}-{platform}"
        extract_binary(archives[platform], f"{prefix}/{binary_name}", target / binary_name)

    repository = Path(__file__).resolve().parents[1]
    shutil.copy2(repository / "LICENSE", args.output / "LICENSE")
    package = {
        "name": args.name,
        "version": version,
        "description": "Native Request Guard MCP inbound request classifier",
        "license": "GPL-3.0-or-later",
        "repository": "https://github.com/rhamenator/request-guard-mcp",
        "bin": {"request-guard-mcp": "bin/request-guard-mcp.js"},
        "engines": {"node": ">=18"},
        "files": ["bin/", "vendor/", "LICENSE", "README.md"],
    }
    (args.output / "package.json").write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    stdio_help = (
        "For a local process MCP client, run `request-guard-mcp --stdio` as the "
        "client's command. The client starts the process and communicates over "
        "stdin/stdout; no HTTP listener or bearer token is used. Grant access only "
        "to clients you trust with the local process environment. PostgreSQL is "
        "not supported in stdio mode.\n\n"
        if supports_stdio else ""
    )
    (args.output / "README.md").write_text(
        f"# {args.name}\n\n"
        "Native Request Guard MCP server for Linux x64 (glibc or musl), Windows x64, macOS Intel, and macOS Apple Silicon. "
        "This package has no runtime npm dependencies and does not download executables during installation.\n\n"
        f"Install with `npm install -g {args.name}@{version}`. Set a unique `AUTH_TOKENS` value "
        "of at least 32 characters, then run `request-guard-mcp`. For local use, set "
        "`MCP__HOST=127.0.0.1`. Connect an HTTP POST MCP client to "
        "`http://127.0.0.1:8085/mcp` using `Authorization: Bearer <your token>`. "
        "The core `classify` and `explain` tools do not require Redis or PostgreSQL.\n\n"
        + stdio_help
        + "For setup, permissions, and transport limits, see "
        "[the repository](https://github.com/rhamenator/request-guard-mcp). "
        "The companion Agensi skill is distributed separately and is not included here.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
