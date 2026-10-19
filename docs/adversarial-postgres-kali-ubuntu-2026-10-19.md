# PostgreSQL outage and recovery from Kali to Ubuntu — 2026-10-19

This is a bounded guest-to-guest test of the release-profile candidate binary,
not of a packaged next release. The binary was built with
`cargo build --release --locked` from main commit
`5800eccb127c0644357a91ded3749623106a03b2` with rustc 1.96.0;
SHA-256: `0f5b890f4922ad863c9c270979dde779751aa6477baa23c7df3ffee4ec5c95ae`.
The intervening merged PR #75 changed test scripts and evidence, not server code.
The candidate still reports version 0.1.1, but it is **not** the published
v0.1.1 binary.

## Lab and procedure

- Ubuntu 26.04 VM `copperfin-ubuntu26-deb` at `192.168.122.73` ran the
  candidate server and PostgreSQL 18.6. Kali VM `copperfin-kali-full` at
  `192.168.122.74` ran Python 3.14.7 and the committed stdlib-only
  `scripts/adversarial_postgres_probe.py`. Both guests were running together.
- PostgreSQL was installed in the Ubuntu guest with `sudo apt-get install -y
  postgresql`. A disposable `copperfin` database role and `request_guard_lab`
  database were created with `sudo -u postgres createuser --login copperfin`
  and `sudo -u postgres createdb --owner=copperfin request_guard_lab`.
- The server bound `192.168.122.73:18091` with a freshly generated synthetic
  64-character bearer token, a fresh 64-character `MCP__AUTH__CACHE_SCOPE_HMAC_KEY`,
  `MCP__POSTGRES__URL=postgresql:///request_guard_lab?host=/var/run/postgresql`,
  and 3-second per-tool/classify timeouts. The token was passed to the probe
  through stdin, not a process argument or published log. Only this lab IP
  and port were probed; no firewall rule was needed.
- From Kali, run the probe with `--url http://192.168.122.73:18091
  --stage healthy` before and after the outage, and with `--stage outage`
  while PostgreSQL is stopped. The exact client form was
  `cat /tmp/request-guard-pg-token | python3 /tmp/adversarial_postgres_probe.py
  --url http://192.168.122.73:18091 --stage STAGE` after copying the two
  repository scripts to `/tmp` in Kali. The probe uses one stable synthetic
  request ID across all three stages.
- In Ubuntu, `sudo pg_ctlcluster 18 main stop` caused the outage;
  `sudo pg_ctlcluster 18 main start` restored the database. The server process
  remained running throughout. The second cycle used the committed probe
  directly, after an initial manual RPC check had confirmed the same behavior.

| Stage | `classify` | `replay_decision` | MCP `ping` |
| --- | --- | --- | --- |
| Before outage | HTTP 200, successful result | HTTP 200, `matches_original=true` | HTTP 200 |
| PostgreSQL stopped | HTTP 200, JSON-RPC `-502 UPSTREAM_ERROR` | HTTP 200, JSON-RPC `-502 UPSTREAM_ERROR` | HTTP 200 |
| After restart | HTTP 200, successful result | HTTP 200, `matches_original=true` | HTTP 200 |

The committed probe reported **3/3** passing checks in each stage (9/9
total). The initial manual check measured 23.1 ms and 1.9 ms for healthy
classify/replay, 12.3 ms and 1.1 ms during outage, and 24.9 ms and 2.7 ms
after recovery. Those are single observations, not a latency benchmark.
The bounded 2,063-byte server log contained no raw lab token. Host full I/O
PSI was 0.00% over 10 and 60 seconds before this VM window. Both VMs were
gracefully shut down afterward. The server process, temporary token, binary,
logs, Kali probe copies, database, and role were removed; PostgreSQL was
stopped in the Ubuntu guest. The PostgreSQL package remains installed there.

This verifies one live PostgreSQL outage/recovery and basic MCP availability
from Kali. It does not cover concurrent database failure, failover replicas,
or the exact packaged next-release artifact. The release gate still requires
bounded sustained load, exact scanner request counts, independent classifier
evasion, packaged client matrix, and independent reviewer reconciliation.
