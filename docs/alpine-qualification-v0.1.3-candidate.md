# Alpine v0.1.3 private candidate qualification

This is **private candidate evidence**, not a public Alpine release. The
published v0.1.2 native and npm packages remain glibc-only on Linux x64.
Issue #54 tracks the remaining support and release work.

## Source and artifacts

The dedicated `request-guard-alpine-3242` libvirt guest was created from the
[official Alpine 3.24.2 x86_64 cloud image](https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/alpine-3.24.2-x86_64-cloudinit-r2.qcow2).
Its SHA-512 matched Alpine's `.sha512` sidecar:
`6b9928cea1c6243affb8a9b09eba6046cd090e8bdb7141fbf0c8f2649c4a99d62e12cda289da41f99de82ce2b3e3780772dd594eaee3693cb49691d81cbe5d4b`.
The guest used 2 vCPUs, 3 GiB RAM, a 12 GiB independent disk, Alpine 3.24.2,
Node 24.18.1, npm 11.12.1, and Python 3.14.7. The guest account password is
in the owner's GNOME Login keyring; neither it nor the SSH key is in the repo.

Private release workflow run
[`39351755924`](https://github.com/rhamenator/request-guard-mcp/actions/runs/39351755924)
from branch commit `d556a036c4b9041b3f5bf3cc11213e6f74a77fd2` passed the
version/source preflight and the Linux glibc, Linux musl, Windows x64, macOS
Intel, and macOS Apple Silicon build, package, startup, Inspector, and checksum
jobs. The musl job additionally ran the packaged binary in Alpine 3.24.2 and
passed health, missing-token rejection, authenticated MCP `initialize`,
`tools/list`, and `classify`. No GitHub release was created.

The private musl archive
`request-guard-mcp-v0.1.3-alpine-candidate-linux-x64-musl.tar.gz` has SHA-256
`5e24259e06c20d3939d83d00a84a589c202cc7bc2822381e64e4eb01cf6b72d2`.
Its sidecar verified on the host and inside Alpine. The extracted binary has
SHA-256 `c19faa49a4e4385b4cb109ad1e0c6f3c9dfe5529eba047bc7b7139cf13c18e88`;
`file` identified a static PIE and `readelf -l` showed no ELF interpreter.
All five private candidate archive sidecars verified after download.

## Guest and cross-VM tests

In the dedicated Alpine guest, the **exact extracted musl binary** passed a
fresh official MCP Inspector run: missing-token rejection, MCP `2025-06-18`
initialization with server version `0.1.3`, 23 tool contracts including
`classify` and `explain`, and successful calls to both core tools. The
synthetic-secret log probe passed 3/3 and found no marker or bearer token in
the bounded test logs.

Kali `copperfin-kali-full` called the same server over the isolated libvirt
network. The server used `MCP__HOST=0.0.0.0`, `MCP__PORT=18886`, and a unique
synthetic `AUTH_TOKENS` value. Existing stdlib probes were copied to Kali and
the token was provided on stdin, never as a command-line argument:

| Probe | Result |
| --- | --- |
| `adversarial_probe.py --url http://ALPINE_IP:18886 --max-request-bytes 1048576` | HTTP/auth/malformed/injection/oversize 10/10 |
| `adversarial_ws_probe.py --host ALPINE_IP --port 18886` | WebSocket/auth/protocol 8/8 |
| `adversarial_classifier_probe.py --url http://ALPINE_IP:18886` | classifier controls and evasions 19/19 |
| `adversarial_envelope_fuzz_probe.py --url http://ALPINE_IP:18886 --cases 128` | malformed envelopes 128/128, recovery passed |

A second listener on port 18887 used `MAX_REQUEST_BYTES=4096` and one-second
HTTP header/body timeouts. Kali's `adversarial_slow_client_probe.py` passed
4/4 incomplete-header, incomplete-body, over-limit chunk, and recovery cases.
A third listener on port 18888 used `MAX_CONNECTIONS=2` and a ten-second header
timeout. Kali's `adversarial_connection_burst_probe.py --attempts 128` observed
128/128 excess connections shed, zero probe exceptions, a 1.7 ms maximum
observed close latency, and authenticated recovery. Synthetic bearer tokens
were absent from all three server logs. Kali was shut down afterward.

The dependency-free npm package was assembled from the **same five verified
private archives**. `npm pack --dry-run` listed the launcher, five native
binaries, license, metadata, and README with no runtime dependency or install
script. A clean local tarball install in Alpine selected the musl binary;
its SHA-256 matched the extracted archive binary. The installed npm command
passed the same five official Inspector checks. The candidate was **not**
published to npm.

## Static linking and limits

The musl artifact is a static PIE with no ELF interpreter or dynamic OpenSSL
dependency. The source selects rustls for reqwest and SQLx, and Cargo.lock
contains no `openssl-sys` or `native-tls` package. These facts reduce libc and
OpenSSL runtime assumptions for the exercised core path. Alpine's package
manager and npm resolved and reached their registries, but that does not prove
the Rust server's optional outbound DNS, TLS certificate trust, Redis,
PostgreSQL, or OTLP integrations on musl. Those integrations need explicit
Alpine tests or documented exclusions before a buyer-facing support claim.
This bounded run also does not prove unlimited denial-of-service resistance,
all classifier evasions, or compatibility with every MCP client.

The Alpine VM was retained for follow-up qualification and is shut down when
not in use. Private candidate archives and the npm tarball remain local only.
