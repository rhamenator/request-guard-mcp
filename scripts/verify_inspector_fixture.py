#!/usr/bin/env python3
"""Check the committed, development-only MCP Inspector npm fixture offline."""

import base64
import json
from pathlib import Path
from urllib.parse import urlparse

from inspector_smoke import EXPECTED_CLIENT_VERSION, EXPECTED_INSPECTOR_VERSION


def main() -> None:
    fixture = Path(__file__).with_name("inspector-fixture")
    manifest = json.loads((fixture / "package.json").read_text())
    lock = json.loads((fixture / "package-lock.json").read_text())
    expected = {"@modelcontextprotocol/inspector": EXPECTED_INSPECTOR_VERSION}
    assert manifest["private"] is True
    assert manifest["devDependencies"] == expected
    assert lock["lockfileVersion"] == 3
    assert lock["packages"][""]["devDependencies"] == expected
    packages = lock["packages"]
    assert packages["node_modules/@modelcontextprotocol/inspector"]["version"] == EXPECTED_INSPECTOR_VERSION
    assert packages["node_modules/@modelcontextprotocol/client"]["version"] == EXPECTED_CLIENT_VERSION
    assert len(packages) > 2
    for name, package in packages.items():
        if not name:
            continue
        url = urlparse(package["resolved"])
        assert url.scheme == "https" and url.hostname == "registry.npmjs.org", name
        algorithm, encoded = package["integrity"].split("-", 1)
        assert algorithm == "sha512" and len(base64.b64decode(encoded, validate=True)) == 64, name
    print(f"PASS locked Inspector {EXPECTED_INSPECTOR_VERSION}, client {EXPECTED_CLIENT_VERSION}, "
          f"{len(packages) - 1} integrity-pinned registry packages")


if __name__ == "__main__":
    main()
