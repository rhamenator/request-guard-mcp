#!/usr/bin/env python3
"""Check ASN evidence fields through a running stdio binary and real Redis."""

import argparse
import json
import os
import socket
import subprocess
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit


def frame(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def redis_command(address, *arguments):
    parts = [str(argument).encode() for argument in arguments]
    request = f"*{len(parts)}\r\n".encode()
    request += b"".join(f"${len(part)}\r\n".encode() + part + b"\r\n" for part in parts)
    with socket.create_connection(address, timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(request)
        with connection.makefile("rb") as response:
            line = response.readline()
    if not line.startswith(b":"):
        raise AssertionError("Redis did not accept the test record")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    redis_url = os.environ["TEST_REDIS_URL"]
    parsed = urlsplit(redis_url)
    if parsed.scheme != "redis" or parsed.password or parsed.username:
        raise ValueError("probe requires the local unauthenticated Redis test service")
    address = (parsed.hostname, parsed.port or 6379)
    prefix = f"request_guard_asn_evidence_{uuid.uuid4().hex}"
    key = f"{prefix}:threats:asn"
    record = json.dumps({"threat_type": "test_listing", "severity": "high",
                         "source": "asn-evidence-probe", "last_seen": None,
                         "metadata": None})
    redis_command(address, "HSET", key, "64501", record)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "asn-evidence-probe", "version": "1"},
        }},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "enrich_asn", "arguments": {"asn": 64502},
        }},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "enrich_asn", "arguments": {"asn": 64501},
        }},
    ]
    try:
        with tempfile.TemporaryDirectory(prefix="rg-asn-evidence-") as cwd:
            env = {"PATH": os.environ.get("PATH", ""), "HOME": cwd,
                   "MCP__AUTH__ENABLED": "false", "MCP__REDIS__URL": redis_url,
                   "MCP__REDIS__KEY_PREFIX": prefix}
            result = subprocess.run(
                [str(binary), "--stdio"], input=b"".join(map(frame, requests)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd,
                timeout=30, check=False,
            )
        if result.returncode:
            raise AssertionError(f"stdio child exited {result.returncode}")
        responses = [json.loads(line) for line in result.stdout.splitlines()]
        if [response.get("id") for response in responses] != [1, 2, 3, 4]:
            raise AssertionError("unexpected stdio response count/order")
        tool = next(tool for tool in responses[1]["result"]["tools"]
                    if tool["name"] == "enrich_asn")
        if not all(field in tool["description"] for field in
                   ("asn_data_found", "reputation_listed")):
            raise AssertionError("ASN evidence fields are not advertised")
        unknown = responses[2]["result"]["structuredContent"]
        listed = responses[3]["result"]["structuredContent"]
        if not (unknown["asn"] == 64502 and unknown["asn_data_found"] is False
                and unknown["reputation_listed"] is False
                and unknown["organization"] is None and unknown["country"] is None
                and unknown["is_hosting"] is False and unknown["risk_score"] == 0.1):
            raise AssertionError("unlisted ASN was not marked as an unverified baseline")
        if not (listed["asn"] == 64501 and listed["asn_data_found"] is False
                and listed["reputation_listed"] is True and listed["risk_score"] == 0.9):
            raise AssertionError("seeded ASN listing was not distinguished from no evidence")
        print("PASS running ASN diagnostic: no-evidence baseline and Redis listing distinguished")
    finally:
        redis_command(address, "DEL", key)


if __name__ == "__main__":
    main()
