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
# the other tools that accept a classify-shaped request: validate the payload, not just HTTP 200
def tool_result(tool, args):
    s, b = post({"jsonrpc": "2.0", "id": n[0] + 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})
    if s != 200 or not isinstance(b, dict) or "error" in b: return None
    r = b.get("result") or {}
    if r.get("isError"): return None
    return r.get("structuredContent") or r
def explain_ok(r): return bool(r) and "robots_violation" in [f.get("name") for f in r.get("factors", [])]
def breakdown_ok(r): return bool(r) and r.get("total_score", 0) >= 0.75 and any("robots_violation" in e.get("signals", []) for e in r.get("breakdown", []))
def batch_ok(r):
    items = (r or {}).get("results") or []
    verdicts = [((i.get("result") or {}).get("verdict"), i.get("error")) for i in items]
    return bool(r) and r.get("errors") == 0 and verdicts == [("block", None), ("allow", None)]
case("explain_applies_field", bool(explain_ok(tool_result("explain", {"classification": {**BASE, "robots_violation": True}}))), lambda g: g is True, "factor robots_violation present, no RPC error")
case("score_breakdown_applies_field", bool(breakdown_ok(tool_result("score_breakdown", {"signals": {**BASE, "robots_violation": True}}))), lambda g: g is True, "total >= block threshold, signal in breakdown")
case("batch_items_independent", bool(batch_ok(tool_result("batch_classify", {"items": [{**BASE, "robots_violation": True}, BASE]}))), lambda g: g is True, "item 0 block, item 1 allow, errors == 0")
# the validators themselves must reject error-shaped results (guards against a pass-on-error probe)
case("validators_reject_errors", [explain_ok(None), breakdown_ok(None), batch_ok(None), batch_ok({"errors": 2, "results": []})], lambda g: not any(g))
# repeated flips never leave residue between requests
seq = [classify({**BASE, "robots_violation": i % 2 == 0})[1][0] for i in range(40)]
case("alternating_40_no_residue", seq[:4], lambda g: seq == ["block", "allow"] * 20)
# the server is still healthy
s, b = post({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": "health", "arguments": {}}})
case("healthy_afterwards", (s,), lambda g: g[0] == 200)
print(json.dumps({"summary": {"passed": sum(results), "total": len(results), "requests": n[0]}}))
sys.exit(0 if all(results) else 1)
