# TLS fingerprint attestation

The MCP server does not terminate client TLS; production deployments place it
behind a TLS proxy and it cannot reconstruct the classified visitor's
ClientHello. Therefore JA3/JA4 values affect rules and cache identity only when
an authenticated upstream also supplies a valid short-lived attestation.

Configure the same random secret (at least 32 bytes) on trusted producers and
this server as `TLS_FINGERPRINT_ATTESTATION_KEY`. The token format is
`v1:<unix-seconds>:<hex HMAC-SHA256>`. Its canonical message is eight
newline-separated UTF-8 fields: version, issued-at, lowercase client IP,
uppercase method, exact path, normalized JA3, canonical JA4, and lowercase
source. Control characters are rejected. The default freshness window is 60
seconds and is configurable with
`TLS_FINGERPRINT_ATTESTATION_MAX_AGE_SECONDS`.

For a rolling rotation, deploy the new value to this downstream consumer as
`TLS_FINGERPRINT_ATTESTATION_KEY` and the old value as
`TLS_FINGERPRINT_ATTESTATION_PREVIOUS_KEY`. This server verifies with either
key. Only after all downstream consumers accept both should upstream producers
switch to the new current key. Remove the previous key after all producers have
rolled and at least the maximum token lifetime has elapsed.

The server consumes `tls_fingerprint_attestation`, derives
`tls_fingerprint_verified` internally, and does not let JSON callers set that
boolean. Invalid, missing, stale, or context-mismatched tokens leave the values
unverified. Unverified values remain format-validated but do not affect rules
or cache keys.

Configure comma-separated normalized threat sets with `TLS_KNOWN_BAD_JA3` and
`TLS_KNOWN_BAD_JA4`. Verified matches emit `tls_fingerprint_known_bad`; a
verified JA4 transport/version profile that conflicts with a modern browser UA
emits `ua_tls_profile_mismatch`. PostgreSQL decision audit JSON contains the
normalized values, source, and server-derived verification status, but not the
short-lived signature.

At the first ingress hop, Envoy must enable JA3/JA4 in its TLS inspector and
overwrite internal headers. Cloudflare values require Enterprise Bot Management
and a Worker adapter reading `request.cf.botManagement.ja3Hash`/`ja4`; they are
not automatic origin headers. Origins must be isolated with trusted proxy
networks, Cloudflare Tunnel, or preferably account-scoped Authenticated Origin
Pulls. See the producer repository's deployment example for that first-hop
boundary.

References: [Envoy TLS inspector](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/listener/tls_inspector/v3/tls_inspector.proto.html),
[Cloudflare Bot Management variables](https://developers.cloudflare.com/bots/reference/bot-management-variables/), and
[Cloudflare Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/).
