#!/usr/bin/env python3
"""Count bounded scanner messages from a full-payload tcpdump capture.

Requires tshark. Nikto requests must each occupy one client TCP segment with
one request line. Nmap service probes must each occupy one TCP stream.
"""

import argparse
import collections
import json
import re
import subprocess


REQUEST_LINE = re.compile(rb"^[A-Z]{2,20} [^\r\n]*\r\n")
EMBEDDED_REQUEST = re.compile(rb"\r\n[A-Z]{2,20} [^\r\n]*\r\n")
CLIENT = "ip.src==192.168.122.74 && tcp.len>0"


def fields(path, display_filter, *names):
    command = ["tshark", "-r", path, "-Y", display_filter, "-T", "fields"]
    for name in names:
        command += ["-e", name]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout.splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--scanner", choices=("nmap", "nikto"), required=True)
    args = parser.parse_args()

    streams = collections.defaultdict(list)
    for line in fields(args.pcap, CLIENT, "tcp.stream", "tcp.payload"):
        stream, payload = line.split("\t", 1)
        streams[int(stream)].append(bytes.fromhex(payload.replace(":", "")))
    payloads = [payload for parts in streams.values() for payload in parts]
    retransmissions = len(fields(
        args.pcap,
        "tcp.analysis.retransmission || tcp.analysis.fast_retransmission",
        "frame.number",
    ))
    http_requests = len(fields(args.pcap, "http.request && ip.src==192.168.122.74", "frame.number"))
    http_responses = len(fields(args.pcap, "http.response", "frame.number"))

    if args.scanner == "nmap":
        # This service scan includes binary probes that are not HTTP requests.
        boundaries_ok = all(len(parts) == 1 for parts in streams.values()) and all(
            payload.count(b"\r\n\r\n") <= 1 for payload in payloads
        )
    else:
        # Every Nikto message starts at a segment boundary, including two
        # intentionally malformed request lines without full HTTP headers.
        boundaries_ok = all(
            REQUEST_LINE.match(payload)
            and payload.count(b"\r\n\r\n") <= 1
            and not EMBEDDED_REQUEST.search(payload)
            for payload in payloads
        ) and http_responses == len(payloads)
    passed = bool(payloads) and retransmissions == 0 and boundaries_ok
    print(json.dumps({
        "scanner": args.scanner,
        "pass": passed,
        "on_wire_messages": len(payloads),
        "tcp_streams": len(streams),
        "decoded_http_requests": http_requests,
        "http_responses": http_responses,
        "retransmissions": retransmissions,
        "message_boundaries_verified": boundaries_ok,
    }))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
