#!/usr/bin/env python3
"""Packaging checks using synthetic archives; no release or npm account needed."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from package_npm import PLATFORMS


class NativeNpmPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="request-guard-npm-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        for platform, (extension, binary_name) in PLATFORMS.items():
            prefix = f"request-guard-mcp-v0.1.1-{platform}"
            archive = self.assets / f"{prefix}.{extension}"
            name = f"{prefix}/{binary_name}"
            binary = (f"#!/bin/sh\nprintf 'native:{platform}:%s\\n' \"$1\"\n".encode()
                      if platform.startswith("linux-") else b"test binary")
            if extension == "zip":
                with zipfile.ZipFile(archive, "w") as package:
                    package.writestr(name, binary)
            else:
                with tarfile.open(archive, "w:gz") as package:
                    member = tarfile.TarInfo(name)
                    member.size = len(binary)
                    member.mode = 0o755
                    package.addfile(member, io.BytesIO(binary))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            archive.with_name(f"{archive.name}.sha256").write_text(
                f"{digest} *{archive.name}\n", encoding="ascii"
            )

    def package(self, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(Path(__file__).with_name("package_npm.py")),
             "--name", "request-guard-mcp", "--version", "v0.1.1",
             "--assets", str(self.assets), "--output", str(output)],
            text=True, capture_output=True,
        )

    def test_verified_archives_produce_offline_native_package(self) -> None:
        output = self.root / "package"
        result = self.package(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((output / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], "0.1.1")
        self.assertNotIn("dependencies", manifest)
        self.assertNotIn("scripts", manifest)
        self.assertNotIn("--stdio", (output / "README.md").read_text(encoding="utf-8"))
        for platform, (_, binary_name) in PLATFORMS.items():
            self.assertTrue((output / "vendor" / platform / binary_name).is_file())
        launched = subprocess.run(
            ["node", str(output / "bin/request-guard-mcp.js"), "probe"],
            text=True, capture_output=True, check=True,
        )
        self.assertEqual(launched.stdout, "native:linux-x64:probe\n")
        musl = subprocess.run(
            ["node", "-e", "const fs = require('node:fs'); "
             "const original = fs.existsSync; "
             "fs.existsSync = path => path === '/lib/ld-musl-x86_64.so.1' || original(path); "
             "process.report.getReport = () => ({header: {}}); "
             "require(process.argv[1])", str(output / "bin/request-guard-mcp.js"), "probe"],
            text=True, capture_output=True,
        )
        self.assertEqual(musl.returncode, 0, musl.stderr)
        self.assertEqual(musl.stdout, "native:linux-x64-musl:probe\n")
        ambiguous = subprocess.run(
            ["node", "-e", "process.report.getReport = () => { throw Error('disabled'); }; "
             "require(process.argv[1])", str(output / "bin/request-guard-mcp.js"), "probe"],
            text=True, capture_output=True,
        )
        self.assertEqual(ambiguous.returncode, 0, ambiguous.stderr)
        self.assertEqual(ambiguous.stdout, "native:linux-x64:probe\n")
        packed = subprocess.run(
            ["npm", "pack", "--dry-run", "--json"], cwd=output,
            text=True, capture_output=True, check=True,
        )
        filenames = {item["path"] for item in json.loads(packed.stdout)[0]["files"]}
        self.assertIn("vendor/linux-x64/request-guard-mcp", filenames)
        self.assertIn("vendor/linux-x64-musl/request-guard-mcp", filenames)
        self.assertIn("vendor/windows-x64/request-guard-mcp.exe", filenames)

    def test_tampered_archive_cannot_create_package(self) -> None:
        archive = self.assets / "request-guard-mcp-v0.1.1-linux-x64.tar.gz"
        with archive.open("ab") as output:
            output.write(b"tampered")
        target = self.root / "rejected"
        result = self.package(target)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
