#!/bin/bash
set -euo pipefail
export PGDATABASE="$DATABASE_URL"
restore_url="${DATABASE_URL%/*}/wallet_security_restore_drill"
unset DATABASE_URL
dump=$(find /backups -maxdepth 1 -name 'wallet-security-*.dump' -type f | sort | tail -1)
test -n "$dump"
sha256sum --check --status "$dump.sha256"
pg_restore --list "$dump" >/dev/null
source_version=$(psql -X -qAt -v ON_ERROR_STOP=1 -c 'SELECT max(version) FROM _sqlx_migrations WHERE success')
source_tables=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
# A stale scratch database is deliberately not overwritten; investigate a failed drill.
psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
CREATE DATABASE wallet_security_restore_drill TEMPLATE template0;
SQL
cleanup() {
  psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
DROP DATABASE wallet_security_restore_drill;
SQL
}
trap cleanup EXIT
export PGDATABASE="$restore_url"
# libpq password stays in environment, never in pg_restore's argument list.
export PGHOST=postgres PGPORT=5432 PGUSER=postgres
PGPASSWORD="${restore_url#postgresql://postgres:}"
export PGPASSWORD="${PGPASSWORD%@*}"
timeout 120 pg_restore --exit-on-error --no-owner --no-acl --dbname=wallet_security_restore_drill "$dump" 2>/dev/null
version=$(psql -X -qAt -v ON_ERROR_STOP=1 -c 'SELECT max(version) FROM _sqlx_migrations WHERE success')
tables=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
test "$version" = "$source_version"
test "$tables" = "$source_tables"
export PGDATABASE="${restore_url%/*}/wallet_security"
printf 'restore_drill_pass migration=%s public_tables=%s archive_sha256=%s\n' "$version" "$tables" "$(sha256sum "$dump" | cut -d' ' -f1)"
