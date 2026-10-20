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
manager and npm resolved and reached their registries. The initial run did not
exercise the Rust server's optional DNS, TLS certificate trust, Redis,
PostgreSQL, or OTLP integrations; the follow-up below tests them on later
private candidates. The server does not implement general outbound fetch.
This bounded run also does not prove unlimited denial-of-service resistance,
all classifier evasions, or compatibility with every MCP client.

The Alpine VM was retained for follow-up qualification and is shut down when
not in use. Private candidate archives and the npm tarball remain local only.

## Optional integration follow-up

On the exact musl binary above, Redis 8.8.0 and PostgreSQL 18.6 installed in
the Alpine guest both reported healthy. A seeded Redis threat lookup returned
the expected record; after a Redis service stop it returned JSON-RPC `-502`
and recovered after restart. PostgreSQL classify, replay, and MCP ping passed
3/3 while healthy, 3/3 during an outage with deterministic `-502` errors for
database-backed calls, and 3/3 after restart. A local generic OTLP gRPC
collector received one trace export through `http://localhost:4317` after a
WebSocket tool call. This exercised hostname resolution and plaintext OTLP on
the musl build. The guest services and server were stopped afterward.

The follow-up also exposed an HTTPS OTLP defect: the initial musl candidate
rejected `https://` collector endpoints at startup because the exporter had no
TLS feature. A private rebuild from `093a572` enabled rustls and native-root
support but still rejected the Alpine guest's locally installed test CA with
`UnknownIssuer`. Commit `7fb371e` explicitly enables native trust roots in
the exporter configuration. Its private release workflow
[`39357791203`](https://github.com/rhamenator/request-guard-mcp/actions/runs/39357791203)
produced a musl archive with SHA-256
`398234b2e421d2c7b0c8c3ac6b7640d54bfc75e57868cf2b348064ef6779dfaf`.
The extracted binary SHA-256 is
`0f72f6d704488ce763dc9021b8b3eef82e0e8aee20844b213479212af5a85c3b`.
The sidecar verified on the host and inside Alpine. The packaged Alpine CI
smoke passed with an HTTPS endpoint configured; that smoke proves startup,
not a successful TLS export.

The **exact extracted binary** then initialized Redis and PostgreSQL in the
Alpine VM, returned healthy backend status, and passed a fresh official MCP
Inspector run: missing-token rejection, initialization, 23 tools, classify,
and explain. PostgreSQL classify/replay/ping passed 3/3 before outage, 3/3
during outage, and 3/3 after restart. A seeded Redis lookup succeeded, failed
with deterministic JSON-RPC `-502` while Redis was stopped, and succeeded
again after restart. A WebSocket probe with a Redis tool call passed 9/9.

For TLS, a local generic OTLP gRPC collector used a one-day test certificate
signed by a CA installed in Alpine's system trust store. With the exporter
pointed at `https://localhost:4318`, the collector received one trace export
after the WebSocket tool call. A second collector on port 4319 used a valid
server certificate signed by a separate CA **not** installed in the guest.
The same tool call passed, but that collector received zero exports and the
server reported `invalid peer certificate: UnknownIssuer`. Eight bounded
server/collector logs contained neither the synthetic bearer token nor the
synthetic cache-scope key. Test certificates, private keys, and collector
scripts remain guest-local and are excluded from all release artifacts.

This proves configured HTTPS OTLP export with Alpine system trust roots and
rejection of an untrusted lab CA for this candidate. It does not prove every
public collector, certificate configuration, or network failure mode.

The private workflow completed successfully on all five targets with no
GitHub release. All five archive sidecars verified after download. The musl
binary is a static PIE with no ELF interpreter; the updated lockfile includes
`rustls-native-certs` and `openssl-probe` for certificate discovery but still
has no `openssl-sys` or `native-tls` package. A dependency-free npm candidate
was built from those exact five archives. Its tarball SHA-256 is
`0cab48eebc3a9dc1a6b8a2d4e3c726b1f7fe22cc3703c3d3cdecd9fb2795edda`.
After a clean local tarball install in Alpine, the selected musl binary hash
matched `0f72f6d704488ce763dc9021b8b3eef82e0e8aee20844b213479212af5a85c3b`.
The installed npm launcher passed the same five official Inspector checks.
The npm candidate was **not** published.

At teardown the lab server and collectors were stopped, Redis and PostgreSQL
test data and synthetic tokens were removed, the test CA was removed from the
Alpine trust store, and the dedicated guest was shut down. The owner's guest
login credential remains in the GNOME Login keyring for future testing. No
test certificate, private key, token, guest disk, candidate archive, or npm
tarball was committed to this repository. This is not a public release.
