#!/usr/bin/env python3
"""Bounded probe of the v1.1.0 robots_violation input against an authorized lab server (token on stdin)."""
import json, sys, urllib.request, urllib.error
url = sys.argv[1]; token = sys.stdin.readline().strip()
H = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": "Bearer " + token, "MCP-Protocol-Version": "2025-06-18"}
FF = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
BASE = {"method": "GET", "path": "/pricing", "user_agent": FF, "ip": "203.0.113.50", "headers": {"Accept": "text/html", "Accept-Language": "en"}}
n = [0]
def post(body):
    n[0] += 1
    req = urllib.request.Request(url + "/mcp", data=json.dumps(body).encode() if not isinstance(body, bytes) else body, headers=H)
    try:
        r = urllib.request.urlopen(req, timeout=5); return r.status, json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode() or "null")
        except Exception: return e.code, None
def classify(args, tool="classify"):
    s, b = post({"jsonrpc": "2.0", "id": n[0] + 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})
    if b and "error" in b: return s, ("error", b["error"].get("code"))
    r = (b or {}).get("result", {}); r = r.get("structuredContent") or r
    if isinstance(r, dict) and "verdict" in r: return s, (r["verdict"], round(r["score"], 2), [x["name"] for x in r.get("signals", [])])
    if isinstance(r, dict) and r.get("isError"): return s, ("toolerror",)
    return s, ("other", str(r)[:60])
results = []
def case(name, got, expect, note=""):
    ok = expect(got); results.append(ok)
    print(json.dumps({"case": name, "got": got, "pass": ok, "note": note}), flush=True)
sig = lambda g: g[2] if len(g) > 2 else None
# the field works and is strictly typed
case("true_blocks", classify({**BASE, "robots_violation": True})[1], lambda g: g[0] == "block" and "robots_violation" in sig(g))
case("false_is_identical_to_absent", classify({**BASE, "robots_violation": False})[1], lambda g: g == classify(BASE)[1] and "robots_violation" not in sig(g))
for label, v in [("string_true", "true"), ("int_one", 1), ("null", None), ("array", [True]), ("object", {"v": True}), ("huge_int", 10**30), ("empty_string", "")]:
    case(f"rejects_{label}", classify({**BASE, "robots_violation": v})[1], lambda g: g[0] in ("error", "toolerror"), "non-boolean must not be coerced")
# the caller cannot smuggle the signal through other channels
case("not_via_extra", classify({**BASE, "extra": {"robots_violation": True}})[1], lambda g: "robots_violation" not in (sig(g) or []))
case("not_via_headers", classify({**BASE, "headers": {**BASE["headers"], "robots_violation": "true"}})[1], lambda g: "robots_violation" not in (sig(g) or []))
case("unknown_neighbour_rejected", classify({**BASE, "robots_violaton": True})[1], lambda g: g[0] in ("error", "toolerror"))
# duplicate keys and raw framing around the field
s, b = post(b'{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"classify","arguments":{"method":"GET","path":"/","user_agent":"x","robots_violation":false,"robots_violation":true}}}')
case("duplicate_key_no_crash", (s,), lambda g: g[0] in (200, 400))
# the other tools that accept a classify-shaped request
s, g = classify({"classification": {**BASE, "robots_violation": True}}, tool="explain"); case("explain_accepts_field", (s, g[0]), lambda g: g[0] == 200)
s, g = classify({"signals": {**BASE, "robots_violation": True}}, tool="score_breakdown"); case("score_breakdown_accepts_field", (s, g[0]), lambda g: g[0] == 200)
s, b = post({"jsonrpc": "2.0", "id": 77, "method": "tools/call", "params": {"name": "batch_classify", "arguments": {"items": [{**BASE, "robots_violation": True}, BASE]}}})
r = ((b or {}).get("result") or {}); r = r.get("structuredContent") or r
case("batch_independent_items", (s, [x.get("verdict") for x in (r.get("results") or r.get("items") or [])][:2]), lambda g: g[0] == 200)
# repeated flips never leave residue between requests
seq = [classify({**BASE, "robots_violation": i % 2 == 0})[1][0] for i in range(40)]
case("alternating_40_no_residue", seq[:4], lambda g: seq == ["block", "allow"] * 20)
# the server is still healthy
s, b = post({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": "health", "arguments": {}}})
case("healthy_afterwards", (s,), lambda g: g[0] == 200)
print(json.dumps({"summary": {"passed": sum(results), "total": len(results), "requests": n[0]}}))
sys.exit(0 if all(results) else 1)
