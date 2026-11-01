#!/bin/bash
# Fixed retained-CID44 resume; optional independently reviewed persistent activation.
set -eu -o pipefail
exec 2>/dev/null
persistent=false
if [ "$#" = 1 ] && [ "$1" = --activate-retained ]; then persistent=true
else [ "$#" = 0 ]; fi
APP=y08cgj4rjem3ldgfmxb11nsp
CID=643b1cc6f975dc11dbae9f3de7e8576b5922b502f3147ec6d076c7aea8902886
NAME=wallet-security-mail-gateway
SOURCE=44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5
IMAGE=wallet-security-mail-gateway:$SOURCE
PROBE=wallet-security-mail-gateway-probe
BINDING=wallet-security-mail-gateway-binding-probe
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
started=false
probe_intent=false
probe_id=''
absence=false
readc() { timeout 2 docker inspect -f "$1" "$2"; }
gateway_owned() {
  [ "$(readc '{{.Id}}' "$CID")" = "$CID" ] &&
  [ "$(readc '{{.Name}}' "$CID")" = "/$NAME" ] &&
  [ "$(readc '{{.Config.Image}}' "$CID")" = "$IMAGE" ] &&
  [ "$(readc '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$CID")" = "$SOURCE" ] &&
  [ "$(readc '{{index .Config.Labels "com.cl8y.scope"}}' "$CID")" = wallet-security-mail-gateway ] &&
  [ "$(readc '{{index .Config.Labels "com.docker.compose.project"}}' "$CID")" = "$APP" ]
}
remove_probe() {
  local pname=$1 scope=$2 pid=$3 owner declared revision actual_scope running
  if [ -z "$pid" ]; then
    local found
    found=$(timeout 3 docker ps -a -q --no-trunc --filter "name=^/$pname$") || return 1
    [ -n "$found" ] || return 0
    [[ "$found" =~ ^[a-f0-9]{64}$ ]] || return 1
    pid=$found
  fi
  [[ "$pid" =~ ^[a-f0-9]{64}$ ]] || return 1
  owner=$(readc '{{index .Config.Labels "com.cl8y.owner"}}' "$pid") || return 1
  actual_scope=$(readc '{{index .Config.Labels "com.cl8y.scope"}}' "$pid") || return 1
  declared=$(readc '{{.Config.Image}}' "$pid") || return 1
  revision=$(readc '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$pid") || return 1
  [ "$owner" = "$APP" ] && [ "$actual_scope" = "$scope" ] && [ "$declared" = "$IMAGE" ] && [ "$revision" = "$SOURCE" ] || return 1
  running=$(readc '{{.State.Running}}' "$pid") || return 1
  if [ "$running" = true ]; then timeout 4 docker stop --time 1 "$pid" >/dev/null || return 1; fi
  timeout 3 docker rm "$pid" >/dev/null
}
cleanup() {
  if [ "$started" = true ]; then
    if gateway_owned && timeout 5 docker stop --time 1 "$CID" >/dev/null && [ "$(readc '{{.State.Running}}' "$CID")" = false ]; then
      printf '%s\n' gateway_noauth_owned_stopped_retained=true
    else printf '%s\n' gateway_noauth_owned_stop_failed; fi
  fi
  if [ "$probe_intent" = true ]; then
    if remove_probe "$PROBE" wallet-security-mail-gateway-preflight "$probe_id"; then printf '%s\n' gateway_noauth_probe_cleanup=true
    else printf '%s\n' gateway_noauth_probe_cleanup_failed; fi
  fi
  if [ "$absence" = true ]; then
    if remove_probe "$BINDING" wallet-security-mail-gateway-binding ''; then printf '%s\n' gateway_noauth_binding_cleanup=true
    else printf '%s\n' gateway_noauth_binding_cleanup_failed; fi
  fi
}
trap cleanup EXIT
trap 'exit 1' TERM INT
# Successful exact-name inventory; refusal is fail-closed before any start/create.
current=$(timeout 3 docker ps -a -q --no-trunc --filter "name=^/$NAME$")
[ "$current" = "$CID" ]
gateway_owned
[ "$(readc '{{.State.Running}}' "$CID")" = false ]
for pname in "$PROBE" "$BINDING"; do
  found=$(timeout 3 docker ps -a -q --no-trunc --filter "name=^/$pname$")
  [ -z "$found" ] || { printf '%s\n' gateway_noauth_preexisting_probe_refused; exit 1; }
done
absence=true
# Pre-start identity binds the actual retained reference to a same-daemon no-start44.
timeout 20 bash "$DIR/runtime-check.sh" "$SOURCE" identity-only
# Exact names AND immutable network IDs, still no network repair.
actual=$(readc '{{range $name,$net := .NetworkSettings.Networks}}{{printf "%s=%s\n" $name $net.NetworkID}}{{end}}' "$CID" | bash "$DIR/normalize-network-names.sh")
expected=$(printf '%s\n' 'wallet-security-mailu-outbound=7afdb422fac3093083ba0ec34934a5acf381449c2cd6c09bb664e44f3b797d35' 'wallet-security-notification=e1f3b89f1f7b590b7fa34def87b39521927b5b28d251189734ebd019b84081b4' | sort)
[ "$actual" = "$expected" ]
[ "$(timeout 2 docker network inspect -f '{{.Internal}}' wallet-security-notification)" = true ]
[ "$(timeout 2 docker network inspect -f '{{.Internal}}' wallet-security-mailu-outbound)" = false ]
[ "$(timeout 2 docker network inspect -f '{{len .Containers}}' wallet-security-notification)" = 0 ]
[ "$(timeout 2 docker network inspect -f '{{len .Containers}}' wallet-security-mailu-outbound)" = 0 ]
printf '%s\n' gateway_noauth_prestart_fixed_identity_and_networks=true
started=true
timeout 5 docker start "$CID" >/dev/null
# Includes live capture and ALL existing image/privilege/network/resource/worker guards.
timeout 25 bash "$DIR/runtime-check.sh" "$SOURCE" topology-only
probe_intent=true
probe_id=$(timeout 4 docker create --name "$PROBE" --network wallet-security-notification --user 10001:10001 --read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 64m --cpus 0.1 --pids-limit 16 --log-driver none --label com.cl8y.scope=wallet-security-mail-gateway-preflight --label "com.cl8y.owner=$APP" --entrypoint /bin/bash "$IMAGE" /app/preflight.sh)
[[ "$probe_id" =~ ^[a-f0-9]{64}$ ]]
printf '{"record":"gateway_reproduction_created","id":"%s"}\n' "$probe_id"
timeout 22 docker start --attach "$probe_id"
[ "$(readc '{{.State.Running}}' "$probe_id")" = false ]
[ "$(readc '{{.State.ExitCode}}' "$probe_id")" = 0 ]
ref=$(readc '{{.Image}}' "$CID"); [[ "$ref" =~ ^sha256:[a-f0-9]{64}$ ]]
printf 'gateway_noauth_tls_preflight_pass workload_source=44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5 retained_cid=%s running_image_ref=%s nat_source_pending=true\n' "$CID" "$ref"
if [ "$persistent" = true ]; then
  # Failures still use the original stop/retain cleanup. Commit persistence only
  # after BOTH owned probe cleanups and one last fixed-CID running readback.
  remove_probe "$PROBE" wallet-security-mail-gateway-preflight "$probe_id"
  probe_intent=false
  printf '%s\n' gateway_noauth_probe_cleanup=true
  remove_probe "$BINDING" wallet-security-mail-gateway-binding ''
  absence=false
  printf '%s\n' gateway_noauth_binding_cleanup=true
  for pname in "$PROBE" "$BINDING"; do
    found=$(timeout 3 docker ps -a -q --no-trunc --filter "name=^/$pname$")
    [ -z "$found" ]
  done
  gateway_owned
  [ "$(readc '{{.State.Running}}' "$CID")" = true ]
  printf 'gateway_activation_final_state retained_cid=%s running=true owned_probes_absent=true\n' "$CID"
  printf 'gateway_activation_pass retained_cid=%s running_image_ref=%s worker_attached=false auth=false sends=0\n' "$CID" "$ref"
  started=false
fi
# Also deliberate failure in activation mode: never enter normal release steps.
exit 1
