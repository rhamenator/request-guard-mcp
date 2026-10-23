#!/usr/bin/env python3
"""Exercise bounded malformed MCP envelopes against an authorized HTTP lab."""

import argparse
import json
import random
import sys
import time

from adversarial_probe import post, rpc


def malformed_case(number, rng):
    """Return a deterministic envelope with one specific expected error."""
    request_id = number + 1
    variant = number % 8
    envelope = {"jsonrpc": "2.0", "id": request_id, "method": "ping"}
    if variant == 0:
        # A valid request missing its final brace must remain a parse error.
        return "truncated_json", json.dumps(envelope).encode()[:-1], -32700, None
    if variant == 1:
        envelope["jsonrpc"] = rng.choice(["1.0", None, True])
        expected_id = None
        expected_code = -32600
        name = "invalid_version"
    elif variant == 2:
        envelope["id"] = rng.choice([[], {}, False])
        expected_id = None
        expected_code = -32600
        name = "invalid_id"
    elif variant == 3:
        envelope["params"] = rng.choice([[], "oops", 42])
        expected_id = request_id
        expected_code = -32600
        name = "scalar_params"
    elif variant == 4:
        envelope.update(method="tools/call", params={})
        expected_id = request_id
        expected_code = -32602
        name = "missing_tool_name"
    elif variant == 5:
        envelope.update(method="tools/call", params={"name": 7})
        expected_id = request_id
        expected_code = -32602
        name = "invalid_tool_name"
    elif variant == 6:
        envelope.update(method="tools/call", params={
            "name": "classify", "arguments": {"user_agent": []},
        })
        expected_id = request_id
        expected_code = -400
        name = "invalid_classify_arguments"
    else:
        envelope.update(method="tools/call", params={
            "name": f"nonexistent-tool-{rng.randrange(1_000_000)}", "arguments": {},
        })
        expected_id = request_id
        expected_code = -404
        name = "unknown_tool"
    return name, json.dumps(envelope, separators=(",", ":")).encode(), expected_code, expected_id


def response_matches(status, response, expected_code, expected_id):
    try:
        reply = json.loads(response)
        return (
            status == 200
            and isinstance(reply, dict)
            and reply.get("jsonrpc") == "2.0"
            and "id" in reply
            and type(reply["id"]) is type(expected_id)
            and reply.get("id") == expected_id
            and "result" not in reply
            and isinstance(reply.get("error"), dict)
            and reply["error"].get("code") == expected_code
        )
    except (ValueError, TypeError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--cases", type=int, default=128)
    args = parser.parse_args()
    if not 1 <= args.cases <= 256:
        parser.error("--cases must be 1..256")
    token = sys.stdin.readline().strip()
    if len(token) < 32:
        parser.error("read a lab bearer token of at least 32 characters from stdin")

    rng = random.Random(0xA11CE)
    failures = []
    start = time.monotonic()
    for number in range(args.cases):
        name, body, expected_code, expected_id = malformed_case(number, rng)
        try:
            status, response = post(args.url, token, body)
            if not response_matches(status, response, expected_code, expected_id):
                failures.append({"case": number, "name": name, "status": status,
                                 "expected_code": expected_code})
        except (OSError, ValueError, TypeError) as error:
            failures.append({"case": number, "name": name,
                             "exception": type(error).__name__})

    try:
        status, response = post(args.url, token, rpc("ping", request_id=999))
        recovered = status == 200 and json.loads(response).get("result") == {}
    except (OSError, ValueError, TypeError):
        recovered = False
    print(json.dumps({
        "case": "bounded_malformed_envelopes",
        "passed": args.cases - len(failures),
        "total": args.cases,
        "seconds": round(time.monotonic() - start, 3),
        "recovery": recovered,
        "failures": failures[:8],
    }), flush=True)
    raise SystemExit(0 if not failures and recovered else 1)


if __name__ == "__main__":
    main()
