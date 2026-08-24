#!/usr/bin/env python3
"""Prompt for MCP stack credentials and securely update .env."""

from __future__ import annotations

import getpass
import secrets
from pathlib import Path

KEYS = (
    "AUTH_TOKENS",
    "CACHE_SCOPE_HMAC_KEY",
    "TLS_FINGERPRINT_ATTESTATION_KEY",
    "REDIS_PASSWORD",
    "POSTGRES_PASSWORD",
    "GRAFANA_ADMIN_PASSWORD",
)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    target = root / ".env"
    if not target.exists():
        target.write_text(
            (root / ".env.example").read_text(encoding="utf-8"), encoding="utf-8"
        )
    values: dict[str, str] = {}
    lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
    for line in lines:
        if line and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.rstrip("\n").split("=", 1)
            values[key] = value
    print("Leave a prompt blank to generate a strong random value.")
    updates: dict[str, str] = {}
    for key in KEYS:
        existing = values.get(key, "")
        keepable = (
            existing if len(existing) >= 32 and "replace_me" not in existing else ""
        )
        while True:
            entered = getpass.getpass(
                f"{key} [{'keep existing' if keepable else 'generate'}]: "
            ).strip()
            value = entered or keepable or secrets.token_urlsafe(36)
            if len(value) >= 32:
                updates[key] = value
                break
            print(f"{key} must contain at least 32 characters.")
    output: list[str] = []
    remaining = dict(updates)
    for line in lines:
        key = (
            line.split("=", 1)[0]
            if "=" in line and not line.lstrip().startswith("#")
            else None
        )
        if key in remaining:
            output.append(f"{key}={remaining.pop(key)}\n")
        else:
            output.append(line)
    output.extend(f"{key}={value}\n" for key, value in remaining.items())
    target.write_text("".join(output), encoding="utf-8")
    target.chmod(0o600)
    print(f"Credentials written to {target}. Run: make docker-compose-up")


if __name__ == "__main__":
    main()
