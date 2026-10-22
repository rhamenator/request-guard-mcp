# Authentication failure log amplification

An independent adversarial source review found a warning on every failed MCP
authorization attempt. A bounded loopback replay against the exact private
`v1.0.0-rc.9` glibc binary sent 128 unauthenticated `POST /mcp` requests. All
returned 401, while the default warning path emitted 128 log lines and 19,712
bytes. The server stayed alive. This is issue #183; no shared VM, Docker image,
or host-wide setting was changed.

This change removes per-request authorization failure logs. The HTTP
401/403 behavior remains, while deployment ingress/access logs can account for
those responses without exposing bearer values in the application log. The
existing `adversarial_log_probe.py` now also sends 64 missing-token and 64
wrong-token requests at debug level. It requires the expected HTTP statuses,
no more than 1 KiB of log growth during that burst, nonempty bounded output,
no authorization failure lines, and no synthetic
token or request marker. The release candidate must be rebuilt and this check
replayed against its exact packaged binary before a stable approval.
