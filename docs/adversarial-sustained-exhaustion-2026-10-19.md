# Bounded sustained slow-header exhaustion — 2026-10-19

## Scope and method

This host-side lab used the debug Request Guard binary with SHA-256
`3dae13d8bc964cc4a0bf0380575f03fcac6349c251446dfc29e299d8766499df`.
The stdlib-only `scripts/adversarial_sustained_exhaustion_probe.py` launched a
fresh server on loopback with a synthetic bearer token, `MAX_CONNECTIONS=2`,
and a ten-second header deadline. For each of 12 cycles, it held two incomplete
HTTP headers for about five seconds, attempted 32 excess connections at a
bounded rate, released the held sockets, and required an authenticated `ping`
to recover. It sampled server RSS, host one-minute load, and host I/O pressure
after every cycle. The server and synthetic token were removed at completion.

Command:

```bash
python3 scripts/adversarial_sustained_exhaustion_probe.py \
  --binary /path/to/built/request-guard-mcp
```

OpenSnitch initially required a temporary exact-executable allow rule for this
loopback test. The rule was removed and the firewall reloaded afterward.

## Observed result

The 63.37-second run passed. All 384 excess connections were shed without
connection errors, and all 12 recovery pings succeeded. The highest observed
excess-connection latency was 3.22 ms. Server RSS rose from 14,916 to
15,488 KiB (572 KiB) and plateaued during later cycles. Sampled host
one-minute load ranged from 0.86 to 1.41; sampled `io.some` ten-second
pressure remained `avg10=0.00`. The probe emits a machine-readable JSON result
that can be captured for each run; the local run output is not part of a
release asset.

## Limitations

This is a controlled 63-second loopback test of one two-slot HTTP listener,
not an unbounded denial-of-service guarantee. It does not measure packet loss,
network middleboxes, multi-process scaling, or the exact packaged next-release
binary. The packaged release and Kali-to-Ubuntu client matrix remain separate
release gates.
