#!/bin/bash
set -euo pipefail
. /app/deploy/libpq.sh
dump=$(find /backups -maxdepth 1 -name 'wallet-security-*.dump' -type f | sort | tail -1)
test -n "$dump"
sha256sum --check --status "$dump.sha256"
pg_restore --list "$dump" >/dev/null
source_version=$(psql -X -qAt -v ON_ERROR_STOP=1 -c 'SELECT max(version) FROM _sqlx_migrations WHERE success')
source_tables=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
source_profiles=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM profiles WHERE id='00000000-0000-0000-0000-000000000001'")
source_events=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM security_events WHERE id='deployment-owned-restore-fixture'")
# A stale scratch database is deliberately not overwritten; investigate a failed drill.
psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
CREATE DATABASE wallet_security_restore_drill TEMPLATE template0;
SQL
cleanup() {
  export PGDATABASE=wallet_security
  psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
DROP DATABASE wallet_security_restore_drill;
SQL
}
trap cleanup EXIT
export PGDATABASE=wallet_security_restore_drill
timeout 120 pg_restore --exit-on-error --no-owner --no-acl --dbname=wallet_security_restore_drill "$dump" 2>/dev/null
version=$(psql -X -qAt -v ON_ERROR_STOP=1 -c 'SELECT max(version) FROM _sqlx_migrations WHERE success')
tables=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
test "$version" = "$source_version"
test "$tables" = "$source_tables"
profiles=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM profiles WHERE id='00000000-0000-0000-0000-000000000001'")
events=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM security_events WHERE id='deployment-owned-restore-fixture'")
test "$profiles" = "$source_profiles"
test "$events" = "$source_events"
export PGDATABASE=wallet_security
printf 'restore_drill_pass migration=%s public_tables=%s archive_sha256=%s owned_profiles=%s owned_events=%s\n' "$version" "$tables" "$(sha256sum "$dump" | cut -d' ' -f1)" "$profiles" "$events"
