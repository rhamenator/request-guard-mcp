# Release policy from 2026-10-27

The public `v1.0.0` tag and artifacts are immutable historical releases. This
policy applies to later Request Guard MCP releases; it does not relabel or
withdraw v1.0.0. Version numbers continue forward. The next feature release
candidate is planned on the `1.1.0-rc.N` line, subject to its own reviewed
scope and version bump. Do not create that tag or move `latest` while the
installer gate below is incomplete.

## Official candidate gate

An official release candidate has the same technical, security, adversarial,
artifact, documentation, and owner self-review requirements as a production
release. Qualify the **exact candidate artifacts**, including checksums,
source-bound GitHub attestations where available, authentic clients, backend
outages and recovery, TLS trust, malformed and exhaustion probes, and buyer
instructions. Repeat relevant checks on the tagged bytes and public registry
digests. An independent human review is encouraged but is not a hard gate for
this non-Copperfin project. Release notes must say explicitly when no
independent human review occurred. An independent LLM review does not count as
human review.

Every platform advertised as supported must have an installer or package that
can be installed and uninstalled on a clean supported system. A portable
archive by itself does not meet this requirement. The qualification matrix
must cover Linux x64 glibc, Linux x64 musl/Alpine, Windows x64, macOS x64, and
macOS arm64 if all five remain advertised. Record the installer format,
artifact digest, source and provenance, clean host/VM, exact install and
uninstall commands, client smoke, residue check, and limitations for each.
The npm package can satisfy a platform only after its launcher is tested from
a clean registry install and removed cleanly on that platform; its Node.js
prerequisite must be disclosed. Do not infer an npm platform pass from a native
archive pass.
The manual `Qualify Published npm Install` workflow provides a five-platform
public-registry install, installed-launcher stdio and Inspector smoke, and
uninstall/residue check. It is preliminary evidence for a published version,
not a substitute for exact candidate installer qualification or owner review.

Commercial code signing and notarization are deferred for lack of funding.
Label unsigned installers explicitly. Keep SHA-256 sidecars and GitHub
artifact attestations where available; neither a checksum nor an unsigned
installer is a substitute for a commercial signature. Explain the resulting
OS trust prompts and installation permissions in buyer instructions.

The owner performs the final self-review against the exact tag, installer
matrix, evidence, and release notes before public publication. The protected
`stable-release` environment remains the owner pause for v1+ tags. The
release workflows currently produce portable native archives and a container,
not a qualified all-platform installer set. Their tagged publication paths
fail closed in `scripts/verify_installer_release_gate.py` until an installer
pipeline and exact-artifact qualification are implemented and reviewed.
Unpublished `workflow_dispatch` candidates remain available for development.

This policy does not turn Request Guard into outbound egress enforcement.
The separate .NET project and the owner-controlled Agensi marketplace ZIP
have their own release decisions.
