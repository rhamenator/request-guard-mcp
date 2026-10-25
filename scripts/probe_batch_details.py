#!/usr/bin/env python3
"""Check batch_classify detail and partial-error contracts on a running binary."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def frame(request):
    return (json.dumps(request, separators=(",", ":")) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    item = {"ip": "192.0.2.1", "user_agent": "GPTBot/1.0", "path": "/"}
    invalid_marker = "RG_SYNTHETIC_INVALID_JA3_4983"
    invalid = {**item, "tls_ja3": invalid_marker}
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "batch-details-probe", "version": "1"},
        }},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    for request_id, arguments in enumerate((
        {"items": [item]},
        {"items": [item], "options": {"include_details": False}},
        {"items": [item], "options": {"include_details": True}},
        {"items": [item, invalid, item], "options": {"fail_fast": False}},
        {"items": [item, invalid, item], "options": {"fail_fast": True}},
        {"items": [item], "options": {"include_detail_RG_SYNTHETIC_SECRET_315": False}},
        {"items": [item, invalid], "options": {"failfast": True}},
    ), 3):
        requests.append({"jsonrpc": "2.0", "id": request_id,
                         "method": "tools/call", "params": {
                             "name": "batch_classify", "arguments": arguments}})
    requests.append({"jsonrpc": "2.0", "id": 10,
                     "method": "tools/call", "params": {
                         "name": "validate_payload", "arguments": {
                             "tool": "batch_classify",
                             "payload": {"items": [item], "options": {
                                 "include_detail_RG_SYNTHETIC_SECRET_315": False}},
                         }}})
    essentials = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMPDIR", "USERPROFILE"}
    env = {key: value for key, value in os.environ.items()
           if key.upper() in essentials}
    with tempfile.TemporaryDirectory(prefix="rg-batch-details-") as cwd:
        env["HOME"] = cwd
        if os.name == "nt":
            env["USERPROFILE"] = cwd
            env["APPDATA"] = cwd
        result = subprocess.run(
            [str(binary), "--stdio"], input=b"".join(map(frame, requests)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd,
            env=env,
            timeout=20, check=False,
        )
    if result.returncode != 0:
        raise AssertionError(f"stdio child exited {result.returncode}")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    if [response.get("id") for response in responses] != list(range(1, 11)):
        raise AssertionError("unexpected stdio response count/order")
    if responses[0].get("result", {}).get("protocolVersion") != "2025-06-18":
        raise AssertionError("initialize failed")
    tool = next(tool for tool in responses[1]["result"]["tools"]
                if tool["name"] == "batch_classify")
    option = tool["inputSchema"]["properties"]["options"]["properties"]["include_details"]
    if option.get("default") is not True:
        raise AssertionError("batch details schema default is not true")
    contents = [response["result"]["structuredContent"] for response in responses[2:6]]
    omitted, suppressed, detailed, partial = contents
    for content in (omitted, suppressed, detailed):
        if content["errors"] != 0 or content["processed"] != 1:
            raise AssertionError("successful batch classification failed")
    for content in (omitted, detailed):
        if not content["results"][0]["result"]["signals"]:
            raise AssertionError("default or explicit details missing signals")
    if suppressed["results"][0]["result"]["signals"] != []:
        raise AssertionError("include_details=false still returned signals")
    verdicts = [content["results"][0]["result"]["verdict"]
                for content in (omitted, suppressed, detailed)]
    if len(set(verdicts)) != 1:
        raise AssertionError("details option changed the verdict")
    if (partial["total"], partial["processed"], partial["errors"]) != (3, 2, 1):
        raise AssertionError("partial batch error counts are wrong")
    if (partial["results"][1]["result"] is not None
            or not partial["results"][1]["error"]
            or partial["results"][2]["result"] is None):
        raise AssertionError("partial batch error/result positions are wrong")
    if responses[6].get("error", {}).get("code") != -400:
        raise AssertionError("fail_fast did not reject the failing item")
    for response in responses[7:9]:
        if (response.get("error", {}).get("code") != -400
                or response.get("error", {}).get("message") != "INVALID_REQUEST"):
            raise AssertionError("unknown batch option was not rejected")
    if responses[9]["result"]["structuredContent"]["valid"] is not False:
        raise AssertionError("validate_payload accepted unknown batch option")
    if b"RG_SYNTHETIC_SECRET_315" in result.stdout + result.stderr:
        raise AssertionError("unknown option name reflected into diagnostics")
    if invalid_marker.encode() in result.stdout + result.stderr:
        raise AssertionError("invalid input reflected into diagnostics")
    print("PASS packaged batch_classify: details default/true/false, partial errors, fail_fast, unknown options rejected")


if __name__ == "__main__":
    main()
