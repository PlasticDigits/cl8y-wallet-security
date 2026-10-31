# Wallet security portal deployment

The deployment is a separate Coolify project, with PostgreSQL, API/static,
notification worker, one-shot migrator and grants jobs, and daily local backups.
Only API port 8080 receives an HTTPS proxy route. PostgreSQL and worker have no
host ports and use a private internal Docker network. Do not attach unrelated
applications or share their databases. Real notification sends and contract
ingestion stay disabled until the lead's exact reviewed configuration enables
them. A healthy deployment does not demonstrate chain protection or delivery.

## Build and release

Use the public Git repository with Coolify's Docker Compose build pack and
`/compose.yml`. Set the exact reviewed Git SHA, disable automatic/preview deploys,
and map only service `api` to `https://security.cl8y.com:8080`. Require valid TLS
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
internal while providers/chain are unconfigured; review explicit endpoint
allowlists and egress before enabling either feature. Keep independent final
security/deployment acceptance open until these checks pass on the final SHA.
