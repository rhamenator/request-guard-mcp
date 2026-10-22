#!/usr/bin/env python3
"""Check a disposable Compose stack without printing credentials or response data."""

import argparse
import base64
import json
from pathlib import Path
import subprocess
import time
import urllib.parse
import urllib.request


def read_env(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    )


def get(url: str, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, response.read(1024 * 1024 + 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--project", default="request-guard-compose-qualify")
    parser.add_argument("--mcp-port", type=int, default=8085)
    parser.add_argument("--prometheus-port", type=int, default=9090)
    parser.add_argument("--grafana-port", type=int, default=3000)
    args = parser.parse_args()
    args.env_file = args.env_file.resolve(strict=True)
    values = read_env(args.env_file)

    def post(method: str, params: dict | None = None) -> dict:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{args.mcp_port}/mcp",
            data=body,
            method="POST",
            headers={
                "Authorization": "Bearer " + values["AUTH_TOKENS"],
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200, "MCP HTTP response was not 200"
            return json.loads(response.read(1024 * 1024 + 1))

    initialized = post("initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "compose-qualification", "version": "1.0"},
    })
    assert initialized.get("result", {}).get("serverInfo"), "MCP initialization failed"
    listing = post("tools/list")
    tools = listing.get("result", {}).get("tools", [])
    assert len(tools) >= 20 and any(tool.get("name") == "classify" for tool in tools), "tool listing failed"
    classified = post("tools/call", {
        "name": "classify",
        "arguments": {
            "user_agent": "compose-synthetic", "ip": "198.51.100.42",
            "method": "GET", "path": "/compose-probe",
        },
    })
    assert classified.get("result", {}).get("isError") is False, "classify failed"

    query = urllib.parse.urlencode({"query": 'up{job="request-guard-mcp"}'})
    for _ in range(20):
        try:
            status, data = get(f"http://127.0.0.1:{args.prometheus_port}/api/v1/query?{query}")
            result = json.loads(data)
            if status == 200 and any(
                item.get("value", [None, None])[1] == "1"
                for item in result.get("data", {}).get("result", [])
            ):
                break
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(2)
    else:
        raise AssertionError("Prometheus MCP scrape did not become up")

    authorization = base64.b64encode(("admin:" + values["GRAFANA_ADMIN_PASSWORD"]).encode()).decode()
    for _ in range(20):
        try:
            status, data = get(
                f"http://127.0.0.1:{args.grafana_port}/api/datasources/uid/request-guard-prometheus",
                {"Authorization": "Basic " + authorization},
            )
            datasource = json.loads(data)
            if status == 200 and datasource.get("url") == "http://prometheus:9090":
                break
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(2)
    else:
        raise AssertionError("Grafana datasource was not provisioned")
    status, data = get(
        f"http://127.0.0.1:{args.grafana_port}/api/datasources/proxy/uid/request-guard-prometheus/api/v1/query?{query}",
        {"Authorization": "Basic " + authorization},
    )
    proxied = json.loads(data)
    assert status == 200 and any(
        item.get("value", [None, None])[1] == "1"
        for item in proxied.get("data", {}).get("result", [])
    ), "Grafana could not query Prometheus"

    root = Path(__file__).resolve().parent.parent
    raw = subprocess.check_output(
        ["docker", "compose", "-p", args.project, "--env-file", str(args.env_file),
         "-f", str(root / "docker/docker-compose.yml"), "ps", "--format", "json"],
        text=True,
    )
    containers = [json.loads(line) for line in raw.splitlines() if line.strip()]
    assert {item["Service"] for item in containers} == {"mcp", "redis", "postgres", "prometheus", "grafana"}
    for item in containers:
        for publisher in item.get("Publishers") or []:
            if publisher.get("PublishedPort", 0) != 0:
                assert publisher["URL"] == "127.0.0.1", "host port is not loopback-bound"
    print(json.dumps({
        "result": "PASS", "services": len(containers), "tools": len(tools),
        "classify": "ok", "prometheus_scrape": "up",
        "grafana_datasource": "query_ok", "published_host_ip": "127.0.0.1",
    }))


if __name__ == "__main__":
    main()
