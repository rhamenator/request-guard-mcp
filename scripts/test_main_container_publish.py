#!/usr/bin/env python3
"""Check the release boundary for automatic main-image publication."""

from pathlib import Path
import tempfile

from main_container_publish import publish_main_image


with tempfile.TemporaryDirectory() as directory:
    manifest = Path(directory) / "Cargo.toml"
    for version, expected in (("0.1.5", True), ("0.2.0-rc.1", True),
                              ("1.0.0", False),
                              ("1.0.0-rc.2", False), ("2.0.0", False)):
        manifest.write_text(f'[package]\nname = "request-guard-mcp"\nversion = "{version}"\n')
        assert publish_main_image(manifest) is expected, version
    for version in ("unstable", "01.0.0"):
        manifest.write_text(f'[package]\nversion = "{version}"\n')
        try:
            publish_main_image(manifest)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unparseable version {version!r} must fail closed")

print("PASS main container publication: experimental only")
