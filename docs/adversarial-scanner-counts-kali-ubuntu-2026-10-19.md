# Bounded Kali scanner request counts — 2026-10-19

This run closes the scanner-count evidence gap from the earlier candidate
Kali-to-Ubuntu test. It used the same release-profile Request Guard candidate
binary, SHA-256 `0f5b890f4922ad863c9c270979dde779751aa6477baa23c7df3ffee4ec5c95ae`,
built from `5800eccb127c0644357a91ded3749623106a03b2`. This is **not** a
packaged next-release asset. PRs #75 and #76 added tests and evidence only;
they did not change the server binary.

## Scope and measurement

- Kali `copperfin-kali-full` (`192.168.122.74`) scanned only Ubuntu
  `copperfin-ubuntu26-deb` (`192.168.122.73`) TCP port 18092. Request Guard
  used a fresh synthetic bearer token, a 4,096-byte request cap, and
  one-second HTTP header/body timeouts. No backend was configured. No
  firewall change was needed.
- Before each scanner, Ubuntu started `tcpdump -i any -s 0 -w FILE host
  192.168.122.74 and tcp port 18092`. Capture stopped immediately after
  that scanner. Both captures reported **zero kernel drops**. Host `tshark`
  4.6.4 inspected the captures. Neither had a TCP retransmission. Each
  nonempty Kali-to-Ubuntu TCP payload frame represented one scanner probe or
  request in these captures; Nmap used one such frame per stream, while Nikto
  reused five streams. This is an on-wire count, including malformed probes
  that an HTTP dissector cannot label as `http.request`.
- Nmap 7.99 command: `nmap -Pn -sT -sV -p 18092 --script
  http-methods,http-headers --max-retries 1 --host-timeout 60s
  192.168.122.73` under a 70-second shell timeout. It finished in 7.45
  seconds. Nikto 2.6.1 command: `nikto -host
  http://192.168.122.73:18092 -maxtime 15s -timeout 2 -nointeractive
  -Tuning 1234 -Pause 0.05` under a 20-second shell timeout. Its own
  maximum-time cutoff ended the scan at 16 seconds with zero transport
  errors. These bounds limited load on the shared host.

| Scanner | Kali payload frames = on-wire probes | HTTP requests decoded | Server HTTP responses | Capture packets / drops |
| --- | ---: | ---: | ---: | ---: |
| Nmap | **30** across 30 streams | 3 | 26 (23 × 400, 3 × 404) | 303 / 0 |
| Nikto | **293** across 5 streams | 287 | 293 (3 × 400, 290 × 404) | 912 / 0 |

The Nmap capture also had 31 initial SYNs: one port check and 30 streams
with application data. Its non-HTTP service probes elicited 400 responses,
unknown paths 404, and no version banner. Nikto sent six request payloads
that `tshark` did not decode as HTTP; their associated responses are included
in the 293-response count. The exact counting commands were:

```bash
tshark -r FILE -Y 'ip.src==192.168.122.74 && tcp.len>0' \
  -T fields -e frame.number | wc -l
tshark -r FILE -Y 'http.request && ip.src==192.168.122.74' \
  -T fields -e frame.number | wc -l
tshark -r FILE -Y 'http.response' -T fields -e http.response.code \
  | sort | uniq -c
tshark -r FILE -Y 'tcp.analysis.retransmission || tcp.analysis.fast_retransmission' \
  -T fields -e frame.number | wc -l
```

The Nmap and Nikto capture hashes were respectively
`c072b182cca82c15ba5e6849c96f780de0e4fcacdd47cacf9593310236b9b216`
and `6cb2ad617f23d1976d9d832148e165c2e9ba76b5706c171f7b7a04862a1a0750`.
Raw captures were not retained or committed. They contained no bearer token
because the scanners ran unauthenticated. Nikto reported four generic
browser/TLS header suggestions (`Permissions-Policy`, HSTS, CSP,
`Referrer-Policy`); those are not confirmed defects for this MCP API behind
a TLS proxy. After both scans, Kali received HTTP 200 from `/health` and the
server process was alive.

Host full I/O PSI was 0.00% over 10 and 60 seconds before the VM window;
after scanning it was 0.00% over 10 seconds and 0.08% over 60 seconds.
The synthetic server process, guest binary/logs, both captures, and capture
helpers were removed. Both VMs were shut down gracefully.

This documents the exact scanner traffic for this candidate and scope. It
does not replace the remaining sustained-load, independent classifier-evasion,
review, or exact packaged-release tests.
