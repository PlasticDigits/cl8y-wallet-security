#!/bin/bash
# Read only the exact existing portal backup identity before a one-shot dump.
set -euo pipefail
portal=${1:?portal UUID required}
[[ "$portal" =~ ^[a-z0-9]{20,32}$ ]]
container="${portal}-backup-1"
source=e44569e45b15dbee4b0347dff742f92bd85bedb2
manifest=sha256:07b476118ac7ca8a8af9653471026d02c0e615ace174231bd50aea06392b607e
config=sha256:556024673401ce7337c00ab54a40230abc6e1ffe45d03a41af27eb1ea7c772d9
test "$(docker inspect -f '{{.State.Running}}' "$container")" = true
test "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$container")" = "$portal"
test "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$container")" = backup
image=$(docker inspect -f '{{.Config.Image}}' "$container")
[[ "$image" = "wallet-security:$source" || "$image" = "git.cl8y.com/code/cl8y-wallet-security@$manifest" ]]
actual=$(docker inspect -f '{{.Image}}' "$container")
[[ "$actual" = "$manifest" || "$actual" = "$config" ]]
test "$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$actual")" = "$source"
test "$(docker exec "$container" id -u)" = 999
mount=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/backups"}}{{println .Type .Name .RW}}{{end}}{{end}}' "$container")
test "$mount" = "volume ${portal}_backups true"
role=$(docker exec "$container" /bin/bash -ec '. /app/deploy/libpq.sh; psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT current_user,(SELECT max(version) FROM _sqlx_migrations WHERE success)"')
test "$role" = 'security_backup|5'
printf 'BACKUP_IDENTITY_VERIFIED source=%s manifest=%s actual_image_field=%s uid=999 project_owned=true service=backup owned_backups_rw=true database_role=security_backup migration=5\n' "$source" "$manifest" "$actual"
exit 1
