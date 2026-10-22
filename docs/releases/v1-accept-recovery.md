# TCP accept resource exhaustion regression

The exact private `v1.0.0-rc.9` Linux x64 archive exits when a transient
file-descriptor shortage makes `TcpListener::accept` fail. The source loop used
`accept().await?`; under a process-local `RLIMIT_NOFILE=64`, 54 loopback idle
sockets caused exit code 1 and `Too many open files (os error 24)`. The server
had a configured 256-connection cap, so that cap did not prevent this failure.
No host-wide limit, VM, or public artifact was changed. This is issue #181.

Development main now retries only connection-aborted/interrupted errors and
resource shortages. Resource errors use bounded backoff and rate-limited logs;
other errors still terminate the listener. The Linux CI Build job runs:

```sh
python3 scripts/probe_accept_recovery.py target/release/request-guard-mcp
```

The probe starts the child with only 64 file descriptors, opens at most 100
loopback sockets, requires an observed accept error without log flooding, then
closes them and requires `/health` to recover. A local development build passed
this probe with one warning line. This does not qualify the older private rc.9
archive: the stable candidate must be rebuilt and replayed on its exact bytes.
