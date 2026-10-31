#!/bin/bash
set -euo pipefail
mode=${PROCESS_MODE:-api}
if [ "$mode" = api ] || [ "$mode" = worker ]; then
  test "$(id -u)" = 10001
  # Check the actual process environment, not just the source Compose mapping.
  for forbidden in POSTGRES_PASSWORD DB_MIGRATOR_PASSWORD DB_API_PASSWORD DB_WORKER_PASSWORD DB_BACKUP_PASSWORD; do
    test -z "${!forbidden+x}"
  done
  (
    . /app/deploy/libpq.sh
    if psql -X -q -v ON_ERROR_STOP=1 -c 'BEGIN; CREATE TABLE public.deployment_ddl_probe(id int); ROLLBACK' >/dev/null 2>&1; then
      printf 'runtime_boundary_failed ddl\n' >&2; exit 1
    fi
    if psql -X -q -v ON_ERROR_STOP=1 -c 'BEGIN; DELETE FROM _sqlx_migrations WHERE false; ROLLBACK' >/dev/null 2>&1; then
      printf 'runtime_boundary_failed migration_write\n' >&2; exit 1
    fi
    # Prove denials came from a working connection with the correct migration history.
    psql -X -qAt -v ON_ERROR_STOP=1 -c 'SELECT count(*) FROM _sqlx_migrations WHERE success' >/dev/null
    if [ "$mode" = worker ]; then
      if psql -X -q -v ON_ERROR_STOP=1 -c "BEGIN; UPDATE sessions SET csrf_token='deployment_probe' WHERE false; ROLLBACK" >/dev/null 2>&1; then
        printf 'runtime_boundary_failed worker_session_write\n' >&2; exit 1
      fi
    fi
  )
  if [ "$mode" = api ]; then
    getent ahostsv4 "${TRUSTED_PROXY_HOST:?}" >/dev/null
  fi
  printf 'runtime_boundary_pass mode=%s uid=10001 admin_env_absent=true ddl_denied=true migration_write_denied=true\n' "$mode"
fi
exec /app/wallet-security-api
