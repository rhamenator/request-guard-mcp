#!/usr/bin/env python3
"""Check packaged classify path signals at sensitive segment boundaries."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    cases = [
        ("/products/configurable-shirt", False),
        ("/docs/administrator-guide", False),
        ("/blog/node.environment-setup", False),
        ("/proc.html", False),
        ("/wp-config.phpish", False),
        ("/backup.sqlish", False),
        ("/docs/server-status-guide", False),
        ("/wp-login.php", False),
        ("/cgi-bin/status", False),
        ("/search?q=/admin", False),
        ("/search%3Fq=/admin", True),
        ("/%3f/admin", True),
        ("/admin", True),
        ("/%252eenv.production", True),
        ("/.env-backup", True),
        ("/.env_prod", True),
        ("/.envrc", True),
        ("/config.json", True),
        ("/administrator", True),
        ("/adminer.php", True),
        ("/admin-login", True),
        ("/admin-dashboard", True),
        ("/admin-ajax.php", True),
        ("/admin-api", True),
        ("/admin-settings", True),
        ("/.envs/", True),
        ("/api/internal-api", True),
        ("/config-prod", True),
        ("/config-staging", True),
        ("/graphql-playground", True),
        ("/swagger-ui-dist/", True),
        ("/swagger-docs", True),
        ("/.env~1", True),
        ("/swagger-ui.html", True),
        ("/admin;jsessionid=1", True),
        ("/admin%00.png", True),
        ("/etc/passwd%00.jpg", True),
        ("/prod.env", True),
        ("/repo.git/config", True),
        ("/wp-config.php", True),
        ("/wp-config.php.bak", True),
        ("/wp-config.php_bak", True),
        ("/wp-config.php-old", True),
        ("/.aws/credentials", True),
        ("/.ssh/id_rsa", True),
        ("/.svn/entries", True),
        ("/.htaccess", True),
        ("/server-status", True),
        ("/phpinfo.php", True),
        ("/backup.sql", True),
        ("/backup.sql_old", True),
        ("/.git-credentials", True),
    ]
    messages = [
        {"jsonrpc": "2.0", "id": index + 1, "method": "tools/call", "params": {
            "name": "classify", "arguments": {
                "path": path, "user_agent": "Mozilla/5.0", "method": "GET",
            },
        }}
        for index, (path, _) in enumerate(cases)
    ]
    payload = b"".join((json.dumps(message, separators=(",", ":")) + "\n").encode()
                       for message in messages)
    with tempfile.TemporaryDirectory(prefix="rg-path-boundary-") as cwd:
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}}
        env["HOME"] = cwd
        result = subprocess.run([str(binary), "--stdio"], input=payload,
                                cwd=cwd, env=env, capture_output=True,
                                timeout=20, check=False)
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if len(responses) != len(cases):
        raise AssertionError("unexpected response count")
    for (path, sensitive), response in zip(cases, responses):
        if "error" in response or response["result"].get("isError"):
            raise AssertionError(f"classify failed for {path}")
        classification = response["result"]["structuredContent"]
        names = {signal["name"] for signal in classification["signals"]}
        if ("path_sensitive" in names) != sensitive:
            raise AssertionError(f"wrong sensitive-path signal for {path}: {names}")
        if not sensitive and classification["verdict"] != "allow":
            raise AssertionError(f"ordinary path produced {classification['verdict']}: {path}")
    print("PASS packaged classify: sensitive path segments retained; ordinary prefixes and query ignored")


if __name__ == "__main__":
    main()
