# Fixed Mailu gateway

This separate resource owns only `deploy/mail-gateway/**`. It does not change
portal settings, compose, hooks, DB credentials, contact-key custody or workers.
Independent review of the exact source is required before runtime provisioning.
SMTP AUTH, sender enablement and mail delivery are outside this gateway phase.

The std-only relay connects only to literal `167.233.253.175:587`, listens on
private port 1587, forwards opaque bytes with four active sessions and bounded
buffers, a five-second connect timeout and a 25-second absolute session deadline.
It accepts no arguments, URLs, credentials or destination configuration, and
logs no stream data. Independent public DNS and hostname-verified STARTTLS
confirmed this fixed endpoint is `mail.cl8y.com`; the backend never resolves the
private `mail.cl8y.com` alias, preventing recursive forwarding.

The gateway alone joins new networks `wallet-security-notification` (internal,
with alias `mail.cl8y.com`) and `wallet-security-mailu-outbound` (outbound).
It has no published ports, mounts, socket, credentials, capabilities or writable
root filesystem and runs as 10001. Only a disposable owned probe joins the
notification network at this phase. API/PG and the current worker stay off it.
A later independently reviewed main overlay may attach only the worker while
preserving its DB-private network and absence of a default route.

The runtime uses a digest-pinned Debian slim base with only the pinned portal
image's OpenSSL libraries and the pinned Rust build image's public CA bundle
copied as TLS tooling. It inherits
no database image volumes or entrypoint, and no database variables/volumes exist.
The image build is offline Rust 1.91 with no third-party crate dependency.

`provision.py` runs from the workstation through only the authorized Coolify
WIRE token and VPN URL. `--create --sha SHA --branch BRANCH` creates a separate
public-source application with instant/automatic/preview deployment disabled;
`--app ID --sha SHA --branch BRANCH` pins and deploys only that verified resource
in raw Compose mode. It never changes the portal UUID. The public SHA is the
only environment variable. Neither the operator token nor an SSH key enters the
image, resource environment, runtime mounts or logs. Every API response remains
in memory; only closed resource IDs/status/receipt formats are printed.

The custom start executes `runtime-check.sh` in the authorized builder, whose
Docker management interface is never mounted into gateway/probe workloads.
It verifies actual container source labels and binds its running image reference
to a no-start create from the newly built tag on that same daemon. The receipt
keeps the observed running reference separate from the built image config
digest, without assuming the daemon uses one identifier type. It checks UID, read-only root, no
published ports/mounts/capabilities/credentials/proxy, exact networks and no
other attachments, then confirms current worker direct SMTP egress is denied.
The owned probe runs with the same nonroot/read-only/capability/resource bounds,
verifies no default routes, direct Mailu/other-port/other-owned-target denial,
private alias resolution, and public-CA/hostname-verified required STARTTLS.
It sends only SMTP negotiation and QUIT, never AUTH/MAIL/RCPT/DATA. Raw OpenSSL,
Docker and provider responses are suppressed. Only fixed pass/failure receipts
are accepted by the workstation receipt reader, tied to its own deployment ID.

The actual NAT/source IP still needs an observed connection/SNAT or receiver
receipt; ingress DNS and workstation TLS success are not proof. That receipt
must precede changing the owned mailbox token's staged TEST-NET restriction.
Source success and successful gateway checks never claim notification delivery.
The worker's explicit delivery switch and API readiness stay false until the
separate owned-only activation/acceptance gate. No pre-migration-6 worker may be
run after SMTP has attempted delivery.

Focused checks: `cargo test --manifest-path deploy/mail-gateway/Cargo.toml
--locked --offline`, shell syntax, provisioner synthetic scope/receipt tests,
and a bounded image build. Runtime preflight happens only after source review.
[Coolify API](https://coolify.io/docs/api/endpoints/applications/create-public-application)
is the primary creation/settings contract.
