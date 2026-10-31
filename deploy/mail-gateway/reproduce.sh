#!/bin/bash
# One bounded exact-44 RAW reproduction, never a release. Always stop only ours.
set -eu -o pipefail
exec 2>/dev/null
[ "$#" = 0 ]
APP=y08cgj4rjem3ldgfmxb11nsp
SOURCE=44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5
NAME=wallet-security-mail-gateway
IMAGE=wallet-security-mail-gateway:$SOURCE
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
intent=false
created_id=''
cleanup() {
  if [ "$intent" = true ]; then
    local cid scope project declared revision
    cid=$created_id
    if [ -z "$cid" ]; then
      # Only after a successful pre-create absence query; a partial up may have committed.
      if ! cid=$(timeout 2 docker inspect -f '{{.Id}}' "$NAME"); then
        printf '%s\n' gateway_topology_cleanup_lookup_failed
        return
      fi
    fi
    [[ "$cid" =~ ^[a-f0-9]{64}$ ]] || { printf '%s\n' gateway_topology_cleanup_identity_refused; return; }
    scope=$(timeout 2 docker inspect -f '{{index .Config.Labels "com.cl8y.scope"}}' "$cid") || { printf '%s\n' gateway_topology_cleanup_lookup_failed; return; }
    project=$(timeout 2 docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$cid") || { printf '%s\n' gateway_topology_cleanup_lookup_failed; return; }
    declared=$(timeout 2 docker inspect -f '{{.Config.Image}}' "$cid") || { printf '%s\n' gateway_topology_cleanup_lookup_failed; return; }
    revision=$(timeout 2 docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$cid") || { printf '%s\n' gateway_topology_cleanup_lookup_failed; return; }
    if [ "$scope" = wallet-security-mail-gateway ] && [ "$project" = "$APP" ] && [ "$declared" = "$IMAGE" ] && [ "$revision" = "$SOURCE" ]; then
      if timeout 5 docker stop --time 1 "$cid" >/dev/null; then
        printf '%s\n' gateway_topology_cleanup_owned_stopped_retained=true
      else printf '%s\n' gateway_topology_cleanup_failed; fi
    else printf '%s\n' gateway_topology_cleanup_identity_refused; fi
  fi
}
trap cleanup EXIT
trap 'exit 1' TERM INT
if ! existing=$(timeout 3 docker ps -a -q --no-trunc --filter "name=^/$NAME$"); then
  printf '%s\n' gateway_topology_absence_query_failed
  exit 1
fi
if [ -n "$existing" ]; then printf '%s\n' gateway_topology_preexisting_container_refused; exit 1; fi
[ "$(timeout 3 docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")" = "$SOURCE" ]
raw=$(curl --proto =https -fsSm 8 "https://git.cl8y.com/code/cl8y-wallet-security/raw/commit/$SOURCE/deploy/mail-gateway/compose.yml")
hash=$(printf '%s\n' "$raw" | sha256sum)
[ "${hash%% *}" = 5fab6231d85b52f1612161cab2e093e1430bd8968874cbd4096463a22f9a3ccb ]
printf '%s\n' gateway_topology_exact44_raw_verified
export SOURCE_SHA=$SOURCE
intent=true
printf '%s\n' "$raw" | timeout 15 docker compose --env-file /dev/null -f - --project-name "$APP" up -d --no-build gateway
created_id=$(timeout 2 docker inspect -f '{{.Id}}' "$NAME")
[[ "$created_id" =~ ^[a-f0-9]{64}$ ]]
printf '{"record":"gateway_reproduction_created","id":"%s"}\n' "$created_id"
# The capture occurs while alive, before even the identity guard; ALL guards remain.
timeout 20 bash "$DIR/runtime-check.sh" "$SOURCE" topology-only
printf '%s\n' gateway_topology_diagnostic_complete_not_runtime_acceptance=true
exit 1
