#!/usr/bin/env python3
"""Globally install, exercise, and uninstall a public or local candidate npm package."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "request-guard-mcp"
RELEASE_ROOT = "https://github.com/rhamenator/request-guard-mcp/releases/download"


def run(*args, env=None, show_output=False):
    options = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
               if os.name == "nt" else {"start_new_session": True})
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", errors="replace",
                               env=env, **options)
    try:
        stdout, stderr = process.communicate(timeout=600)
    except subprocess.TimeoutExpired as error:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           capture_output=True, timeout=30, check=False)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise TimeoutError(f"timed out: {args[0]}") from error
    if process.returncode:
        raise RuntimeError(f"{args[0]} exited {process.returncode}: "
                           f"{stderr[-2000:]} {stdout[-1000:]}")
    if stdout and show_output:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    return stdout


def download(url, destination):
    request = urllib.request.Request(url, headers={"User-Agent": "request-guard-release-qualification"})
    with urllib.request.urlopen(request, timeout=90) as response:
        destination.write_bytes(response.read())


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_release_binary(root, version, folder, binary, assets=None):
    extension = "zip" if folder.startswith("windows") else "tar.gz"
    name = f"request-guard-mcp-v{version}-{folder}.{extension}"
    archive = assets / name if assets else root / name
    sidecar = assets / f"{name}.sha256" if assets else root / f"{name}.sha256"
    if assets is None:
        base = f"{RELEASE_ROOT}/v{version}"
        download(f"{base}/{name}", archive)
        download(f"{base}/{name}.sha256", sidecar)
    elif not archive.is_file() or not sidecar.is_file():
        raise AssertionError(f"candidate native archive or sidecar missing: {archive}, {sidecar}")
    listed_hash = sidecar.read_text().split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", listed_hash):
        raise AssertionError("release sidecar has no SHA-256 digest")
    if sha256_file(archive) != listed_hash:
        raise AssertionError("release archive does not match its SHA-256 sidecar")
    if extension == "zip":
        with zipfile.ZipFile(archive) as package:
            members = [name for name in package.namelist() if name.endswith("/" + binary)]
            if len(members) != 1:
                raise AssertionError("release archive has unexpected binary count")
            return package.read(members[0])
    with tarfile.open(archive, "r:gz") as package:
        members = [member for member in package.getmembers()
                   if member.isfile() and member.name.endswith("/" + binary)]
        if len(members) != 1:
            raise AssertionError("release archive has unexpected binary count")
        extracted = package.extractfile(members[0])
        if extracted is None:
            raise AssertionError("release binary could not be read")
        return extracted.read()


def platform_binary():
    if sys.platform == "win32":
        return "windows-x64", "request-guard-mcp.exe"
    if sys.platform == "darwin":
        if platform.machine() not in {"arm64", "x86_64"}:
            raise RuntimeError("unsupported macOS architecture")
        return ("macos-arm64" if platform.machine() == "arm64" else "macos-x64"), "request-guard-mcp"
    if sys.platform == "linux":
        architecture = platform.machine()
        if architecture not in {"x86_64", "AMD64"}:
            raise RuntimeError(f"unsupported Linux architecture: {architecture}")
        libc = platform.libc_ver()[0]
        if libc not in {"glibc", ""}:
            raise RuntimeError(f"unrecognized Linux libc: {libc}")
        return ("linux-x64" if libc == "glibc" else "linux-x64-musl"), "request-guard-mcp"
    raise RuntimeError("unsupported operating system")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tarball", type=Path,
                        help="local unpublished candidate npm tarball")
    parser.add_argument("--native-version",
                        help="Cargo/native version shown by the candidate binary")
    parser.add_argument("--tarball-sha256",
                        help="expected SHA-256 of the local candidate tarball")
    parser.add_argument("--assets", type=Path,
                        help="local native archives and SHA-256 sidecars from the same candidate run")
    args = parser.parse_args()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-rc\.\d+)?", args.version):
        parser.error("expected a numeric release or rc version")
    if len({bool(args.tarball), bool(args.assets), bool(args.tarball_sha256),
            bool(args.native_version)}) != 1:
        parser.error("--tarball, --tarball-sha256, --assets, and --native-version must be supplied together")
    if args.tarball and not re.fullmatch(r"[0-9a-f]{64}", args.tarball_sha256):
        parser.error("--tarball-sha256 must be a lowercase SHA-256 digest")
    if args.native_version and not re.fullmatch(r"\d+\.\d+\.\d+(?:-rc\.\d+)?", args.native_version):
        parser.error("--native-version must be a numeric release or rc version")
    if args.tarball and not args.tarball.is_file():
        parser.error(f"candidate npm tarball is not a file: {args.tarball}")
    if args.assets and not args.assets.is_dir():
        parser.error(f"candidate native assets directory is missing: {args.assets}")
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not npm:
        raise RuntimeError("npm is required")
    folder, binary = platform_binary()
    with tempfile.TemporaryDirectory(prefix="request-guard-public-npm-",
                                     ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        prefix = root / "prefix"
        env = os.environ.copy()
        env["NPM_CONFIG_USERCONFIG"] = str(root / "empty.npmrc")
        (root / "empty.npmrc").write_text("")
        env["NPM_CONFIG_REGISTRY"] = "https://registry.npmjs.org/"
        env["NPM_CONFIG_IGNORE_SCRIPTS"] = "true"
        package_spec = f"{PACKAGE}@{args.version}"
        if args.tarball:
            tarball = args.tarball.resolve()
            if sha256_file(tarball) != args.tarball_sha256:
                raise AssertionError("candidate npm tarball does not match expected SHA-256")
            package_spec = str(tarball)
        else:
            metadata = json.loads(run(npm, "view", package_spec, "dist.integrity", "--json", env=env))
            if not isinstance(metadata, str) or not metadata.startswith("sha512-"):
                raise AssertionError("registry did not return a SHA-512 integrity value")
            tarball_name = run(npm, "pack", package_spec, "--pack-destination", str(root),
                               "--json", "--ignore-scripts", env=env)
            packed = json.loads(tarball_name)
            tarball = root / packed[0]["filename"]
            actual_integrity = "sha512-" + base64.b64encode(
                hashlib.sha512(tarball.read_bytes()).digest()).decode()
            if actual_integrity != metadata:
                raise AssertionError("registry tarball does not match dist.integrity")

        installed = (prefix / "node_modules" / PACKAGE if os.name == "nt"
                     else prefix / "lib" / "node_modules" / PACKAGE)
        shim_dir = prefix if os.name == "nt" else prefix / "bin"
        shim = shim_dir / ("request-guard-mcp.cmd" if os.name == "nt"
                           else "request-guard-mcp")
        installed_successfully = False
        try:
            run(npm, "install", "-g", "--prefix", str(prefix), "--no-audit",
                "--no-fund", "--ignore-scripts", package_spec, env=env)
            installed_successfully = True
            manifest = json.loads((installed / "package.json").read_text())
            if manifest["name"] != PACKAGE or manifest["version"] != args.version:
                raise AssertionError("registry install returned a different package")
            if (manifest.get("scripts") or manifest.get("dependencies") or
                    manifest.get("optionalDependencies") or manifest.get("bundledDependencies") or
                    (installed / "binding.gyp").exists()):
                raise AssertionError("published package gained install hooks or runtime dependencies")
            if not shim.is_file():
                raise AssertionError("npm did not install the global command shim")
            native = installed / "vendor" / folder / binary
            if not native.is_file():
                raise AssertionError(f"missing installed native binary for {folder}")
            expected = expected_release_binary(root, args.version, folder, binary, args.assets)
            if native.read_bytes() != expected:
                raise AssertionError("npm native binary differs from expected native archive")
            digest = hashlib.sha256(expected).hexdigest()
            run(sys.executable, str(ROOT / "scripts/stdio_release_smoke.py"),
                "--binary", str(shim), "--expected-version", args.native_version or args.version,
                env=env, show_output=True)
            run(sys.executable, str(ROOT / "scripts/inspector_smoke.py"),
                "--expected-version", args.native_version or args.version, str(shim),
                env=env, show_output=True)
        finally:
            if installed_successfully:
                run(npm, "uninstall", "-g", "--prefix", str(prefix), "--no-audit",
                    "--no-fund", PACKAGE, env=env)
            shims = ([shim_dir / f"request-guard-mcp{suffix}"
                      for suffix in ("", ".cmd", ".ps1")]
                     if os.name == "nt" else [shim])
            if installed.exists() or any(os.path.lexists(path) for path in shims):
                raise AssertionError("npm uninstall left the package or global shim behind")
        mode = "candidate" if args.tarball else "public"
        print(f"PASS {mode} global npm {PACKAGE}@{args.version}: {folder} sha256:{digest}; "
              "stdio, Inspector, uninstall, no package/shim residue")


if __name__ == "__main__":
    main()
