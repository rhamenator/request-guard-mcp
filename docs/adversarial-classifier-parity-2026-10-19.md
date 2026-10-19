# Independent classifier-evasion corpus — 2026-10-19

The Rust AI Scraping Defense classifier lists `masscan`, `nikto`, `sqlmap`,
and `httpclient` as known suspicious user-agent names and treats `/internal`
and `/xmlrpc.php` as disallowed paths (`crates/asd-detection/src/lib.rs`).
Request Guard's inbound classifier had a narrower signature set. This corpus
tests the shared concepts through Request Guard's actual authenticated MCP
HTTP interface. The projects remain independent; no code or runtime
dependency was imported.

## Black-box finding and fix

Before the change, the release-profile Request Guard candidate binary with
SHA-256 `0f5b890f4922ad863c9c270979dde779751aa6477baa23c7df3ffee4ec5c95ae`
returned HTTP 200 but only `ua_non_browser` for the four scanner names and no
signal for `/internal` or `/xmlrpc.php`. A benign `Mozilla/5.0` request to
`/welcome` had no signal. The probe used a fresh synthetic bearer token on a
temporary loopback port and removed the server process afterward.

The change adds the four names to `ua_scraper` with word boundaries and adds
the two paths to `path_sensitive` with path/query boundaries. These are
heuristic risk signals, not claims that a self-declared user agent is
authentic or that Request Guard controls the origin's routing. The new
false-positive controls require `/internalized` and `/xmlrpc.phpish` to remain
unflagged.

`scripts/adversarial_classifier_probe.py` now has 19 bounded cases, including
the new corpus and controls. Against a fresh `cargo build --locked` debug
binary (SHA-256
`8fdad081208fb7930de8c84bbfb3758c8995d0a6bf5d67f93c2e7954f24d87b8`),
the full `python3 scripts/ci_adversarial_smoke.py --binary PATH` run passed:
19/19 classifier cases, 128/128 malformed envelopes, 128/128 connection
shedding attempts, and all existing HTTP, WebSocket, backend-unavailable,
slow-client, and synthetic-log checks. `cargo fmt --check`, all seven
focused `engines::rules` tests, and the full `cargo test --locked -q` suite
passed. The first full-suite attempt timed out connecting to loopback because
OpenSnitch blocked the newly built test executables. After allowing those
two exact executable paths and reloading OpenSnitch, the suite passed; the
temporary rules were removed after testing. CI will independently rerun the
suite on the PR.

This closes the selected cross-project signature gap but does not prove that
all obfuscated scanner names or origin-specific path normalizations are
recognized. The exact packaged next-release binary still needs client and
adversarial retesting before release.
