#!/usr/bin/env python3
"""Clean-install, exercise, and uninstall an exact public npm release."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "request-guard-mcp"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=300, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-rc\.\d+)?", args.version):
        parser.error("expected a numeric release or rc version")

    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not npm:
        raise RuntimeError("npm is required")
    with tempfile.TemporaryDirectory(prefix="request-guard-public-npm-") as directory:
        root = Path(directory)
        prefix = root / "prefix"
        env = os.environ.copy()
        env["NPM_CONFIG_USERCONFIG"] = str(root / "empty.npmrc")
        (root / "empty.npmrc").write_text("")
        env["NPM_CONFIG_REGISTRY"] = "https://registry.npmjs.org/"
        env["NPM_CONFIG_IGNORE_SCRIPTS"] = "true"
        package_spec = f"{PACKAGE}@{args.version}"
        run(npm, "install", "--prefix", str(prefix), "--no-audit", "--no-fund",
            "--ignore-scripts", package_spec, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        installed = prefix / "node_modules" / PACKAGE
        manifest = json.loads((installed / "package.json").read_text())
        if manifest["name"] != PACKAGE or manifest["version"] != args.version:
            raise AssertionError("registry install returned a different package")
        if manifest.get("scripts") or manifest.get("dependencies"):
            raise AssertionError("published package gained install scripts or runtime dependencies")
        shim = prefix / "node_modules" / ".bin" / (
            "request-guard-mcp.cmd" if os.name == "nt" else "request-guard-mcp"
        )
        if not shim.is_file():
            raise AssertionError("npm did not install the command shim")
        if sys.platform == "win32":
            folder, binary = "windows-x64", "request-guard-mcp.exe"
        elif sys.platform == "darwin":
            folder = "macos-arm64" if platform.machine() == "arm64" else "macos-x64"
            binary = "request-guard-mcp"
        else:
            libc = platform.libc_ver()[0]
            folder = "linux-x64-musl" if libc != "glibc" else "linux-x64"
            binary = "request-guard-mcp"
        native = installed / "vendor" / folder / binary
        if not native.is_file():
            raise AssertionError(f"missing installed native binary for {folder}")
        digest = hashlib.sha256(native.read_bytes()).hexdigest()

        run(sys.executable, str(ROOT / "scripts/stdio_release_smoke.py"),
            "--binary", str(shim), "--expected-version", args.version, env=env)
        run(sys.executable, str(ROOT / "scripts/inspector_smoke.py"),
            "--expected-version", args.version, str(shim), env=env)

        run(npm, "uninstall", "--prefix", str(prefix), "--no-audit", "--no-fund",
            PACKAGE, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if installed.exists() or shim.exists():
            raise AssertionError("npm uninstall left the package or command shim behind")
        print(f"PASS public npm {package_spec}: {folder} sha256:{digest}; "
              "stdio, Inspector, uninstall, no package/shim residue")


if __name__ == "__main__":
    main()
