#!/bin/bash
# Read-only Coolify builder diagnostic. No workload credential is printed, saved
# to a file, or passed as a command argument. Always fail the build afterwards,
# so Coolify never reaches stop/recreate for existing application services.
set -euo pipefail
app=${1:?application UUID required}
sha=${2:?exact source SHA required}
[[ "$app" =~ ^[a-z0-9]{20,32}$ && "$sha" =~ ^[0-9a-f]{40}$ ]]
api="$app-api-1"
private="${app}_private"
image=$(docker inspect -f '{{.Config.Image}}' "$api")
revision=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
test "$revision" = "$sha"
configured_user=$(docker inspect -f '{{.Config.User}}' "$api")
names=$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{println}}{{end}}' "$api")
grep -Fxq "$private" <<< "$names"
# Docker stdout goes only to this shell variable in helper memory, never logs.
snapshot=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$api")
forbidden=false
database_present=false
trusted_proxy_matches=false
trusted_proxy=''
while IFS= read -r assignment; do
  case "$assignment" in
    DATABASE_URL=*) DATABASE_URL=${assignment#*=}; export DATABASE_URL; database_present=true ;;
    TRUSTED_PROXY_HOST=*) trusted_proxy=${assignment#*=} ;;
    POSTGRES_PASSWORD=*|DB_MIGRATOR_PASSWORD=*|DB_API_PASSWORD=*|DB_WORKER_PASSWORD=*|DB_BACKUP_PASSWORD=*) forbidden=true ;;
  esac
done <<< "$snapshot"
unset snapshot assignment
proxy_name=$(docker inspect -f '{{.Name}}' coolify-proxy)
proxy_image=$(docker inspect -f '{{.Config.Image}}' coolify-proxy)
proxy_managed=$(docker inspect -f '{{index .Config.Labels "coolify.managed"}}' coolify-proxy)
proxy_ip=$(docker inspect -f '{{with index .NetworkSettings.Networks "coolify"}}{{.IPAddress}}{{end}}' coolify-proxy)
test "$proxy_name" = /coolify-proxy && test "$proxy_managed" = true
[[ "$proxy_image" == traefik:* && "$proxy_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
if [ "$trusted_proxy" = coolify-proxy ] || [ "$trusted_proxy" = "$proxy_ip" ]; then trusted_proxy_matches=true; fi
printf 'ACTUAL_API_GUARD configured_user=%s forbidden_env=%s database_present=%s trusted_proxy_matches=%s\n' "$configured_user" "$forbidden" "$database_present" "$trusted_proxy_matches"
printf 'ACTUAL_PROXY name=coolify-proxy image=%s managed=true edge_ipv4=%s\n' "$proxy_image" "$proxy_ip"
export PGCONNECT_TIMEOUT=10
set +e
result=$(timeout 20 docker run --rm --read-only --tmpfs /tmp:size=16m,mode=1777 --cap-drop ALL --security-opt no-new-privileges:true --network "$private" --user "$configured_user" -e DATABASE_URL -e PGCONNECT_TIMEOUT --entrypoint /bin/bash "$image" -c 'id -u; . /app/deploy/libpq.sh; exec psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT current_user,(SELECT count(*) FROM _sqlx_migrations WHERE success)"' 2>&1)
status=$?
set -e
unset DATABASE_URL
sql_verified=false
password_auth_failed=false
probe_uid=false
if grep -Fxq 10001 <<< "$result"; then probe_uid=true; fi
if [ "$status" = 0 ] && grep -Fxq 'security_api|5' <<< "$result"; then sql_verified=true; fi
if [[ "$result" == *'password authentication failed'* ]]; then password_auth_failed=true; fi
unset result
printf 'ACTUAL_API_SQL uid_10001=%s role_and_migration5=%s password_auth_failed=%s\n' "$probe_uid" "$sql_verified" "$password_auth_failed"
printf 'READ_ONLY_PROBE_COMPLETE existing_services_untouched=true\n'
exit 1
