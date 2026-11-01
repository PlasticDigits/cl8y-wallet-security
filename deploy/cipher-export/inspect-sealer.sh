#!/bin/bash
# Recover only this owned sealer's image/mount binding after local state loss.
# Control-plane BUILD observation only; always fail before any start phase.
set -euo pipefail
resource=${1:?sealer UUID required}
portal=${2:?portal UUID required}
[[ "$resource" =~ ^[a-z0-9]{20,32}$ && "$portal" =~ ^[a-z0-9]{20,32}$ ]]
container="seal-$resource"
expected=git.cl8y.com/code/cl8y-wallet-security-backup-seal@sha256:f86972fceca8c2032380cf272d1a9043520080da7a213c1e1ad38b006eb460a9
configured=$(docker inspect -f '{{.Config.Image}}' "$container")
printf 'SEAL_BINDING_OBS configured=%s\n' "$configured"
test "$configured" = "$expected"
test "$(docker inspect -f '{{.State.Running}}' "$container")" = true
actual=$(docker inspect -f '{{.Image}}' "$container")
inspected_id=$(docker image inspect -f '{{.Id}}' "$expected")
source=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$expected")
printf 'SEAL_BINDING_OBS actual=%s inspected_id=%s source=%s\n' "$actual" "$inspected_id" "$source"
[[ "$actual" = "${expected##*@}" || "$actual" = sha256:49bae27daf43dad0ea75c035dffae5e4e91f5b10f08daac8c61b19e5259e8cb1 ]]
# The reviewed raw registry manifest binds the config digest. This daemon's
# image .Id, like container .Image, can report that manifest instead of config.
[[ "$inspected_id" = "${expected##*@}" || "$inspected_id" = sha256:49bae27daf43dad0ea75c035dffae5e4e91f5b10f08daac8c61b19e5259e8cb1 ]]
test "$source" = 6ba5c8c8bcfba6b9b523ecabda4036f72f64a429
mounts=$(docker inspect -f '{{range .Mounts}}{{println .Type .Name .Destination .RW}}{{end}}' "$container")
printf 'SEAL_BINDING_MOUNTS_BEGIN\n%s\nSEAL_BINDING_MOUNTS_END\n' "$mounts"
volumes=$(printf '%s\n' "$mounts" | awk '$1=="volume" {print}')
test "$(printf '%s\n' "$volumes" | wc -l)" = 2
grep -Fxq "volume ${portal}_backups /backups false" <<< "$volumes"
grep -Fxq "volume ${resource}_sealed /encrypted true" <<< "$volumes"
# Reject any other bind/volume, allowing only the declared private /tmp tmpfs.
test -z "$(printf '%s\n' "$mounts" | awk '$1!="volume" && !($1=="tmpfs" && $2=="/tmp") {print}')"
printf 'SEAL_BINDING_VERIFIED image_manifest=%s reviewed_image_config=%s actual_image_field=%s inspected_image_id=%s source=%s input=%s output=%s input_ro=true output_rw=true\n' \
  "${expected##*@}" sha256:49bae27daf43dad0ea75c035dffae5e4e91f5b10f08daac8c61b19e5259e8cb1 \
  "$actual" "$inspected_id" 6ba5c8c8bcfba6b9b523ecabda4036f72f64a429 "${portal}_backups" "${resource}_sealed"
exit 1
