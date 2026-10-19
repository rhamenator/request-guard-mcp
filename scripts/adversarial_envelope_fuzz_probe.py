#!/usr/bin/env python3
"""Exercise bounded malformed MCP envelopes against an authorized HTTP lab."""

import argparse
import json
import random
import sys
import time

from adversarial_probe import post, rpc


ACCEPTED_ERRORS = {-32700, -32600, -32601, -32602, -404}


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
        envelope = {
            "jsonrpc": rng.choice(["2.0", "1.0", None, True, [], {}]),
            "id": rng.choice([0, "x", None, False, [], {}]),
            "method": rng.choice(["nonexistent.method", 7, None, [], {}]),
            "params": rng.choice([None, [], {}, "oops", 42]),
        }
        body = json.dumps(envelope, separators=(",", ":")).encode()
        if number % 4 == 0:
            body = body[: rng.randrange(1, len(body))]
        try:
            status, response = post(args.url, token, body)
            reply = json.loads(response)
            code = reply.get("error", {}).get("code") if isinstance(reply, dict) else None
            if status != 200 or code not in ACCEPTED_ERRORS:
                failures.append({"case": number, "status": status, "code": code})
        except (OSError, ValueError, TypeError) as error:
            failures.append({"case": number, "exception": type(error).__name__})

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
