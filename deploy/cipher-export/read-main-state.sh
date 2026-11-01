#!/bin/bash
# Read-only fixed portal metadata. No ENV, logs, files, restart or mutation.
set -u
portal=qri1j8vhtwwb9akyxfiw73gc
for service in api worker postgres; do
  container="$portal-$service-1"
  if ! timeout 5 docker inspect "$container" >/dev/null 2>&1; then
    printf 'MAIN_STATE service=%s container_absent_or_inspection_failed=true\n' "$service"
    continue
  fi
  project=$(timeout 5 docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$container")
  if [ "$project" != "$portal" ]; then
    printf 'MAIN_STATE service=%s project_scope_mismatch=true\n' "$service"
    continue
  fi
  timeout 5 docker inspect -f "MAIN_STATE service=$service state={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} image={{.Image}} configured_image={{.Config.Image}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" "$container"
done
container="$portal-postgres-1"
project=$(timeout 5 docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$container" 2>/dev/null || true)
if [ "$project" = "$portal" ]; then
  printf 'MAIN_SQLX_BEGIN\n'
  if ! timeout 10 docker exec "$container" psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d wallet_security -c 'BEGIN READ ONLY; SELECT version,success FROM public._sqlx_migrations ORDER BY version; COMMIT;'; then
    printf 'MAIN_SQLX_READ_FAILED\n'
  fi
  printf 'MAIN_SQLX_END\n'
fi
