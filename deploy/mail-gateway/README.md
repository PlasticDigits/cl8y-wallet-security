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

Labels use a string sequence so Coolify can append its managed labels without
introducing numeric mapping keys. The explicit Traefik disable remains present.

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

The short custom build executes its hook from the imported source (Coolify strips
Git metadata before building),
verifies all five image inputs against a strict checksum manifest fetched from
that immutable public commit over HTTPS, and invokes a fixed direct Docker build with
only public SOURCE_SHA. This avoids Coolify Compose-command rewriting and
working-directory env-file assumptions. Its literal command tokens comply with
Coolify shell-safe API validation; no inline shell operators or validation bypass
are used. Generated env files are excluded from
the build context. The custom start executes `runtime-check.sh` in the authorized builder, whose
Docker management interface is never mounted into gateway/probe workloads.
It verifies actual container source labels and binds its running image reference
to a no-start create from the newly built tag on that same daemon. The receipt
keeps the observed running reference separate from the built image config
digest, without assuming the daemon uses one identifier type. It checks UID, read-only root, no
published ports/mounts/capabilities/credentials/proxy, exact networks, actual memory/CPU/PID/no-new-privileges bounds and no
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

## Coordinated read-only observer

`--observe --app y08cgj4rjem3ldgfmxb11nsp --sha OPS_SHA --branch BRANCH`
selects the independently reviewed `observe.sh` as this app's build hook. It
preserves runtime env and the start hook, reads only fixed gateway and
`seal-3nolvrgyhudkv3itihuyuim9` metadata, and deliberately exits 1 before any
application stop/start step. There are no Docker run/create/start/stop/remove,
filesystem-content or SMTP operations. Only selected image/user/mount metadata,
HostConfig, gateway network names/IDs/flags/aliases and only fixed gateway/sealer/managed-proxy
member identities, plus redacted other/self-observer counts and finite owned-project
network events and environment **names** are emitted. Environment values and
mount source paths are never emitted. Unrelated network member names/IDs and
unknown event member IDs are redacted. No extra workload is inspected to
classify the observer itself; its own namespace hostname is only a count hint. If containment removed the gateway, its
absence is explicit; surviving owned networks/events do not imply a runtime
pass. The receiver accepts only closed typed records. The gateway image source
remains the fixed reviewed `44a2d36...`; observer Git source is a separate pin.

## One stopped-after-capture topology reproduction

`--reproduce` is a separate, independently reviewed diagnostic action, not a
release. It uses the existing exact image/source `44a2d36...` and fetches only
that commit's RAW Compose declaration, verifying its fixed SHA-256 before using
it from memory with a public source value and `/dev/null` env-file. No normal
preview, credentials, worker attachment, network repair, proxy settings, image
build or TLS/AUTH/send is used.

A successful exact-name, no-truncation daemon inventory must prove absence
before creation intent; a failed read never means absence. The newly created
CID is retained in memory and cleanup checks that CID, app project, scope,
declared image and source-44 label. Partial-create fallback uses the same gates
and bounded reads. The fixed gateway must be absent before the action. While the newly created
owned gateway is alive, `capture.sh` emits closed network name/ID/internal/member
and alias records before assertions. Unknown member identities are redacted.
The existing identity, privilege, exact-network, resource and direct-worker-
egress guards remain intact; network names, isolation and membership have
separate failure stages. Diagnostic mode stops before TLS and emits no normal
runtime acceptance receipt. The EXIT/TERM cleanup verifies only this app's
newly owned gateway and stops it by ID, retaining its metadata. It never removes
that container or another service. Success and failure both deliberately end
with a failed build so no normal release continuation runs. Restore normal
configuration separately, without deploying, after collecting the evidence.
