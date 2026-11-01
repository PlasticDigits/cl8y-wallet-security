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

## Off-host capture and incident recovery

The separate sealer is public-recipient-only, uid999, read-only root, no
capabilities or network, with the portal's dump volume mounted read-only. Its
framework-resolved output volume must be bound to actual daemon Mount.Name and
RW flags; the raw requested name alone is insufficient. The current confirmed
mapping is retained only in private operator metadata. Only one completed age
cipher/checksum pair is kept. `pause` acknowledges quiescence only after commit
and validates header/hash/source age <=25h; pause flags are tmpfs-only and never
part of the archive. Every capture needs a fresh pause acknowledgement.

The deployed Coolify native S3 helper passes storage credentials through its
CLI/config mechanism. This workflow does not invoke it. Operator-only Boto3
uses explicit credentials transiently in memory from the authorized platform,
with SDK logging disabled and hash-locked dependencies. The operator client derives
the signing region from an exact official Hetzner location endpoint, following
[Hetzner's Boto3 example](https://docs.hetzner.com/storage/object-storage/getting-started/using-libraries/),
without changing the shared platform storage configuration. No S3/operator/private
age/contact credential enters the sealer or temporary transport. A separate
reviewed temporary transport may receive only a scoped, expiring ciphertext-read
capability through protected runtime ENV and operator header. Platform-managed
runtime secret storage is distinct from unmanaged local credential files.

Uploads require a per-volume private-KV CAS lease plus local process lock,
completed fresh pair, exact resource/context/image/volume binding, private-only
transport and complete ciphertext SHA256 validation BEFORE S3. An independent
operator-KV cipher ledger binds source/migration/hash outside the S3 write
boundary. Content-addressed objects are not rewritten just to refresh their age.
The destination must be a NEW owned private never-versioned bucket: four-day
expiry eligibility, one-day aborted multipart cleanup, full policy readback,
and no shared-bucket lifecycle changes. UTC rounding and provider asynchronous
execution mean expiry eligibility is not a promise of exact physical deletion.
Only the latest inner dump avoids nested retention amplification.

After an operator-host restart, recover missing local configuration through
read-only reconciliation before running any provision or capture command.
Resolve the single exact portal by name and pinned live source; read its
project/environment/destination/server relationships and the single owned
sealer. Reconstruct the expected sealer declaration from the committed
`compose.backup-sealer.yml`, reviewed producer image and fresh custody public
recipient, then compare the complete actual declaration and resource context.
Do not run `provision-backup-sealer.py` as a discovery command: it requests start.
The historical runtime receipt alone does not authorize setting
`daemon_binding_verified`; reobserve the exact current daemon mount names,
read/write flags and image before restoring that field.

Read `wallet-security/offhost-lease` from the existing identity-scoped private
KV before claiming the volume. Retain every unresolved task/export intent,
including its resource identity, even when its lease has expired. An absent
local file, elapsed TTL or copied configuration cannot clear the remote
journal. Reconcile each exact task's execution and each exact export resource,
daemon and private listener; do not resume the producer or release a claim
while any queued/late execution or cleanup remains unknown. Search owned
service names for a create with a lost response before creating another helper.
Recover an existing bucket only with the independently retained creation and
owner evidence; an empty, accessible or similarly named bucket is insufficient.

The reviewed ciphertext exporter artifact is manifest
`sha256:7d90ccdec7b196b15401c2f5063795ed86a337d591a35e2521239db84698b6c0`,
config `sha256:69d2e358c750593464b9590cfe48d37b3b04617fadd41e49501b57ae8d32878b`,
source `f5e40b588ccb00ba3d4712bfccd1200b42bd8a45`. Recovered configuration must
retain both `export_image` and `export_image_config_digest`. The observer
checks the configured manifest, pinned-reference image ID and source separately;
container `.Image` and image `.Id` may match only that reviewed manifest or
config. Neither raw field is relabeled as an observed config digest: on the
deployed daemon both fields report the manifest, while the hash-verified raw
registry manifest establishes its config mapping. A local
image fixture remains distinct from actual private binding and export proof.

The conditional daily continuation uses the operator's existing broker on the
BB server/workstation, with only the selected Coolify credentials in operator
memory. It installs no operator identity or S3 credential into a workload and
creates no unmanaged credential file; routine no-print certificate login keeps
the existing private CLI token cache. The native BB definition is enabled for
03:20 UTC daily with a ten-minute outer limit. Its stored runner is byte-bound
to reviewed source, checks frozen controller hashes and private routes, and
CAS-persists only a released clean journal and owned state without erasing newer
history. Failures route one closed, rate-limited notice to the existing agent
owner; unknown intents remain held. Repository merge does not enable or update
an automation definition by itself.

This requires the BB server/operator host, private WG routes, existing valid
certificate/broker/venv, and Coolify/S3 reachability. The observed wg0 service
is active but its unit is disabled at boot. No reboot-safe coverage is claimed.
Server-side daily dumps remain independent; the controller accepts source age
at most25 hours. Daily copy phase drift can yield up to49 hours of source-point
lag, plus any failed/paused or host/BB/VPN outage; this is not a <=24-hour RPO.
Stale/no completed pair and cleanup/policy failures fail visibly and remain
agent-owned. The successful native-context run is recorded in
[`2026-11-01-native-offhost-automation-proof.json`](../deploy/receipts/2026-11-01-native-offhost-automation-proof.json).
The separately retained inactive proposal records the original reviewed input,
not the definition's current enabled state.

Off-host restore proof downloads only the exact owned object, verifies its full
cipher hash against the independent KV ledger, retrieves recovery material
fresh from the scoped vault, and passes the private age identity by inherited
pipe only. It restores into an offline disposable PostgreSQL container with no
published ports or API/delivery/chain workers, compares every SQLx version and
checksum to the pinned source, and removes the scratch resource. A contact-key
canary is owned and exists only in scratch; it is not evidence of real recipient
delivery or real-user contact recovery.

A real incident promotion remains fenced: outbound and mutating API stay off
until the lost-state window and current authoritative chain state are
reconciled. Invalidate ALL restored sessions/challenges and one-use contact
pairing/verification tokens. Preserve original deadlines, attempts, delivery
uncertainty and other audit evidence. Wall-clock maturity alone must not resume
old profile/contact changes; require fresh authorized confirmation when state is
uncertain. Do not replay uncertain outbox items automatically. Never run a pre-6
worker against a database containing SMTP transport rows. These are recovery
procedures, not mutations to current live authentication or state during drills.

The actual post-trial schema-6 offhost recovery receipt is
[`2026-11-01-posttrial-schema6-4fbe039.json`](../deploy/receipts/2026-11-01-posttrial-schema6-4fbe039.json).
It verifies three sent SMTP rows with first-attempt metadata, complete saved
assignment/contact/event and outbox metadata preservation, and zero active
sessions for the present owned trial profile before scratch auth invalidation.
This one-off proof does not establish unattended coverage.
