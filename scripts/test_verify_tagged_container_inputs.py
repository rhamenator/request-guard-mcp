#!/usr/bin/env python3
"""Fail closed on missing or changed tagged container inventories."""

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

from verify_tagged_container_inputs import verify


with TemporaryDirectory() as temp:
    root = Path(temp)
    expected = {}
    for arch in ("amd64", "arm64"):
        (root / arch).mkdir()
        expected[arch] = {}
        for stage in ("builder", "runtime", "toolchain"):
            data = f"{arch}/{stage}\n".encode()
            (root / arch / f"{stage}.txt").write_bytes(data)
            expected[arch][stage] = hashlib.sha256(data).hexdigest()
    qualification = {"container_input_sha256": expected}
    verify(qualification, root)
    (root / "arm64" / "runtime.txt").write_text("changed\n")
    try:
        verify(qualification, root)
    except ValueError as error:
        assert "arm64/runtime" in str(error)
    else:
        raise AssertionError("changed inventory accepted")
    (root / "arm64" / "runtime.txt").unlink()
    try:
        verify(qualification, root)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("missing inventory accepted")
