#!/usr/bin/env python3
"""Verify the checked-in Windows resource contains exactly the source ICO icons."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parent.parent
ICO = ROOT / "assets" / "app-icon.ico"
RC = ROOT / "assets" / "app-icon.rc"
RES = ROOT / "assets" / "app-icon.res"


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def verify() -> None:
    if RC.read_text(encoding="utf-8").strip() != '1 ICON "app-icon.ico"':
        raise ValueError("resource script must contain only the source icon")

    ico = ICO.read_bytes()
    if len(ico) < 6 or (u16(ico, 0), u16(ico, 2)) != (0, 1):
        raise ValueError("invalid ICO header")
    count = u16(ico, 4)
    if not 1 <= count <= 32 or len(ico) < 6 + 16 * count:
        raise ValueError("invalid ICO image count")
    entries = [ico[6 + 16 * i : 6 + 16 * (i + 1)] for i in range(count)]
    images = []
    for entry in entries:
        size, offset = u32(entry, 8), u32(entry, 12)
        if size == 0 or offset < 6 + 16 * count or offset + size > len(ico):
            raise ValueError("invalid ICO image bounds")
        images.append(ico[offset : offset + size])

    res = RES.read_bytes()
    resources = []
    position = 0
    while position < len(res):
        if position + 32 > len(res):
            raise ValueError("truncated resource header")
        size, header_size = u32(res, position), u32(res, position + 4)
        if header_size < 32 or position + header_size + size > len(res):
            raise ValueError("invalid resource bounds")
        if u16(res, position + 8) != 0xFFFF or u16(res, position + 12) != 0xFFFF:
            raise ValueError("resource type and name must be numeric")
        kind, name = u16(res, position + 10), u16(res, position + 14)
        payload = res[position + header_size : position + header_size + size]
        if position == 0 and (kind, name, size) == (0, 0, 0):
            pass  # Standard empty resource header.
        else:
            resources.append((kind, name, payload))
        position = (position + header_size + size + 3) & ~3
    if position != len(res):
        raise ValueError("unexpected trailing resource data")

    icons = {name: payload for kind, name, payload in resources if kind == 3}
    groups = [payload for kind, _, payload in resources if kind == 14]
    if len(resources) != count + 1 or len(icons) != count or len(groups) != 1:
        raise ValueError("resource contains missing, duplicate, or extra entries")
    if Counter(icons.values()) != Counter(images):
        raise ValueError("resource icon bytes differ from source ICO")

    group = groups[0]
    if len(group) != 6 + 14 * count or (u16(group, 0), u16(group, 2), u16(group, 4)) != (0, 1, count):
        raise ValueError("invalid resource icon group")
    for index, ico_entry in enumerate(entries):
        group_entry = group[6 + 14 * index : 6 + 14 * (index + 1)]
        icon_id = u16(group_entry, 12)
        if group_entry[:12] != ico_entry[:12] or icons.get(icon_id) != images[index]:
            raise ValueError("resource icon group differs from source ICO")

    print(f"PASS Windows resource: {count} icons match ICO; no extra resources")


if __name__ == "__main__":
    verify()
