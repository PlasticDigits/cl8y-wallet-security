# Wallet security portal deployment

The deployment is a separate Coolify project, with PostgreSQL, API/static,
notification worker, one-shot migrator and grants jobs, and daily local backups.
Only API port 8080 receives an HTTPS proxy route. PostgreSQL and worker have no
host ports and use a private internal Docker network. Do not attach unrelated
applications or share their databases. Real notification sends and contract
ingestion stay disabled until the lead's exact reviewed configuration enables
them. A healthy deployment does not demonstrate chain protection or delivery.

## Build and release

Use the public Git repository with Coolify's Docker Compose build pack,
**Raw (deploy file as-is)** enabled, and `/compose.yml`. Normal mode can attach
all networks and inject every secret into each container; it is unsuitable for
this privilege boundary. Set the exact reviewed Git SHA and disable automatic/
preview deploys. The explicit Traefik labels route only service `api` to
`https://security.cl8y.com:8080` on the existing external `coolify` proxy network. Require valid TLS
and HTTP-to-HTTPS redirect. The frontend is built with `npm ci` and Rust with
`cargo build --locked`; upstream build/runtime images are digest pinned.
The runtime runs as uid/gid 10001 without capabilities, with a read-only root
filesystem, bounded resources and logs. Never mount the Docker socket.

Generate six independent 32-byte hex secrets in deployment process memory and
send them to Coolify's protected runtime environment API. `deploy/env.example`
lists placeholders, never actual values. Neither app runtime receives the
bootstrap or migration credential. Preserve the contact encryption key in the
authorized workload secret store across database restore and image rollback.
Losing it makes existing encrypted contacts unreadable.
All credentials must have `is_runtime=true` and `is_buildtime=false`; only the
public `SOURCE_SHA` is a build variable. Disable Dockerfile ARG injection and
enable all-value log redaction. Normal build-time values can become command
arguments even in raw mode. Do not print API environment/configuration/log
responses. Coolify manages its own protected runtime files; do not create local
expanded dotenv files. Verify nonempty values, because Compose parsing creates
empty variable entries before credentials are provisioned.

`deploy/coolify-release.py` enforces raw mode, runtime-only secret flags, exact
published branch/SHA, disabled automatic/preview deploys and explicit custom
Compose paths. Run it through
`bao-exec --only COOLIFY_WIRE_TOKEN,COOLIFY_URL -- python3 deploy/coolify-release.py`
with `--app`, `--branch` and `--sha` nonsecret arguments. `--postgres-only` provisions
only storage before a final source pin. `--deployment` reads allowlisted status;
`--receipts` returns only fixed nonsecret boundary/backup/restore receipt lines.
Raw custom-start commands execute inside the builder: use relative
`--env-file .env -f compose.yml` and the preserved host project directory;
Coolify's automatically injected host env-file path is inaccessible there.

The live proxy network already contains an unrelated `postgres` DNS alias.
API resolves that alias differently when it joins both proxy and private
networks; worker private-only access succeeds. Preserve the reviewed runtime
hook `b8aa303154b25d3017816c258b0daeb8954b7b26` on every release. It changes
only API's database hostname to the deployment's unique PostgreSQL container
name, keeps the same protected password, and preserves all volumes, roles,
origin and proxy trust. Its temporary JSON contains a literal secret reference,
never an expanded credential. Record hook SHA separately from workload SHA.
The release helper defaults to this exact hook and verifies command readback.
Use `--image-digest sha256:...` to deploy the already tested public manifest
without rebuilding. Custom commands must remain within the observed 255-byte
storage limit; the helper uses compact commands and checks their lengths.

PostgreSQL init creates separate NOSUPERUSER/NOCREATEDB/NOCREATEROLE identities.
The migrator alone gets schema ownership and `RUN_MIGRATIONS=true`. It exits
before the grants job restricts SQLx history to SELECT for both runtimes.
API/worker never migrate. Their startup checks the schema; public readiness is
`/healthz` with `source_sha`, `migration` and database `server_time`. Worker
health checks a recent heartbeat with the matching SHA. Its transaction advisory
lock serializes competing replicas. Do not enable provider credentials or
arbitrary RPC URLs as part of a deployment test.

## Backup, restore and rollback

`pgdata` and `backups` are persistent named volumes. The backup service uses a
read-only database identity, creates bounded custom-format dumps, verifies the
archive catalogue, atomically renames complete files, hashes them, and retains
seven days. Protect these volumes and the Coolify environment store with host
disk/backups access controls. Local backups do not protect against host loss;
off-host encrypted replication must be independently enrolled and verified
before production acceptance. Do not claim an off-host backup exists without a
restore receipt. Back up the encryption key separately using the secret store.

Before every release, take a fresh backup and record the previous immutable
image/SHA. Restore only into a new isolated database: verify the archive hash,
`pg_restore --list`, restore with `--exit-on-error --no-owner --no-acl`, compare
schema migration versions and non-sensitive owned-sandbox counts, then drop the
scratch database. Never run a restore drill against the serving database. Record
only timestamps, hashes, migration versions, result booleans and counts; do not
publish dump contents, environment/config expansions or contact information.
The one-shot `restore-drill` service performs archive hash/catalogue checks and
restores into the dedicated, newly created `wallet_security_restore_drill`
database, reports only version/table-count/hash, and drops it on exit. A stale
scratch database causes a failure rather than an overwrite. Its bootstrap
credential never reaches API/worker. Preserve the job exit result as evidence.
For the focused disposable storage check, build the final image with its exact
`SOURCE_SHA` label, then run `python3 deploy/check-storage.py --image IMAGE --sha SHA
--migration 6`. This uses the image's real SQLx migrator and grants, compares the
complete successful version/checksum history to exact pinned Git objects,
checks runtime DDL/history/session-write denials, and performs backup/restore.
It publishes no ports and removes only its randomly named sandbox resources.
Do not substitute synthetic migration metadata for latest-schema evidence.

Rollback an application to the previous exact image/SHA only if its schema is
compatible. Do not automatically reverse migrations. For incompatible changes,
stop API/worker, preserve current volumes, restore into a new isolated volume,
apply roles/grants, verify readiness and owned-sandbox behavior, then switch the
route. Keep the old volume until the independent review accepts the recovery.

## Acceptance evidence

Record exact live URL and deployed Git SHA; TLS success; `/healthz` SHA, migration
and server time; advancing matching worker heartbeat; API and worker nonroot
users; no DB host port; runtime DDL/history-write denials; backup hash and isolated
restore results; and a bounded owned-sandbox smoke test with no real recipients
or mainnet transactions. Inspect actual Coolify-generated networking because
platform parsing may attach extra networks. Restrict Coolify administration to
the existing VPN and its authorized credential path. Worker egress remains
internal while providers/chain are unconfigured. Before enabling either feature,
provision a dedicated outbound gateway permitting only the lead's reviewed
finalized RPC and provider endpoints; attach worker to that gateway's internal
network (no shared application network or published ports), inject provider
credentials only through Coolify, and verify both permitted and denied egress.
Do not merely attach the worker to the shared `coolify` network. Keep independent final
security/deployment acceptance open until these checks pass on the final SHA.

## November 1 email runtime

The [schema-6 production receipt](../deploy/receipts/2026-11-01-mail-runtime-4fbe039.json)
binds the tested public image, independently reviewed runtime hook, successful
owned email trial and fresh encrypted off-host restore. The hook in
[`deploy/mail-runtime.sh`](../deploy/mail-runtime.sh) keeps SMTP credentials only
in the worker and attaches only that worker to the private notification network.
`stage` disables delivery, `sandbox` permits only the fixed owned test mailbox,
and `production` removes that test restriction after accepted delivery/recovery
proof. The API and PostgreSQL remain outside the notification network.

Coolify may remove old containers before calling a custom start hook. The hook
therefore accepts only a successful empty service inventory, verifies the exact
existing PostgreSQL volume before recreation, and refuses ambiguous or failed
inventories. It never rolls an SMTP worker back to a pre-migration-6 version.
Unattended off-host enrollment, Telegram credentials and on-chain activation
retain separate acceptance; this receipt does not assert them complete.
