#!/bin/bash
# Runs only in the authorized deployment builder; never mounts Docker into a workload.
set -eu -o pipefail
exec 2>/dev/null
sha=$1
mode=${2-}
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ "$mode" = "" || "$mode" = topology-only || "$mode" = identity-only ]]
if [ "$mode" = topology-only ]; then
  timeout 8 bash "$DIR/capture.sh"
fi
[[ "$sha" =~ ^[0-9a-f]{40}$ ]]
name=wallet-security-mail-gateway
image=wallet-security-mail-gateway:$sha
stage=identity
created=false
binding_id=''
BINDING=wallet-security-mail-gateway-binding-probe
binding_cleanup() {
  if [ "$created" = true ]; then
    local bid scope owner declared revision
    bid=$binding_id
    if [ -z "$bid" ]; then bid=$(timeout 2 docker inspect -f '{{.Id}}' "$BINDING") || return; fi
    [[ "$bid" =~ ^[a-f0-9]{64}$ ]] || return
    scope=$(timeout 2 docker inspect -f '{{index .Config.Labels "com.cl8y.scope"}}' "$bid") || return
    owner=$(timeout 2 docker inspect -f '{{index .Config.Labels "com.cl8y.owner"}}' "$bid") || return
    declared=$(timeout 2 docker inspect -f '{{.Config.Image}}' "$bid") || return
    revision=$(timeout 2 docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$bid") || return
    if [ "$scope" = wallet-security-mail-gateway-binding ] && [ "$owner" = y08cgj4rjem3ldgfmxb11nsp ] && [ "$declared" = "$image" ] && [ "$revision" = "$sha" ]; then
      timeout 3 docker rm "$bid" >/dev/null
    else
      printf '%s\n' gateway_binding_cleanup_identity_refused
      return 1
    fi
  fi
}
trap binding_cleanup EXIT
trap 'printf "mail_gateway_runtime_failed stage=%s\n" "$stage"' ERR
[ "$(docker inspect -f '{{.Config.User}}' "$name")" = '10001:10001' ]
[ "$(docker inspect -f '{{.Config.Image}}' "$name")" = "$image" ]
[ "$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")" = "$sha" ]
[ "$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$name")" = "$sha" ]
# Bind actual running reference to a no-start create from the freshly built tag
# on this daemon. Daemons may expose a manifest ref or a config ID in .Image.
existing=$(timeout 3 docker ps -a -q --no-trunc --filter "name=^/$BINDING$")
[ -z "$existing" ]
created=true
binding_id=$(timeout 3 docker create --name "$BINDING" --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --label com.cl8y.scope=wallet-security-mail-gateway-binding --label com.cl8y.owner=y08cgj4rjem3ldgfmxb11nsp --entrypoint /app/mail-gateway "$image")
[[ "$binding_id" =~ ^[a-f0-9]{64}$ ]]
image_ref=$(docker inspect -f '{{.Image}}' "$name")
[ "$image_ref" = "$(docker inspect -f '{{.Image}}' "$binding_id")" ]
[ "$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$binding_id")" = "$sha" ]
config_digest=$(docker image inspect -f '{{.Id}}' "$image")
binding_cleanup
created=false
if [ "$mode" = identity-only ]; then
  [ "$(docker inspect -f '{{.State.Running}}' "$name")" = false ]
else
  [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ]
fi
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$name")" = true ]
[ "$(docker inspect -f '{{len .HostConfig.PortBindings}}' "$name")" = 0 ]
[ "$(docker inspect -f '{{len .Mounts}}' "$name")" = 0 ]
[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$name")" = false ]
[ "$(docker inspect -f '{{len .HostConfig.CapAdd}}' "$name")" = 0 ]
[ "$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$name")" = '["ALL"]' ]
[ "$(docker inspect -f '{{index .Config.Labels "traefik.enable"}}' "$name")" = false ]
[ "$(docker inspect -f '{{.HostConfig.LogConfig.Type}}' "$name")" = none ]
stage=credentials
keys=$(docker inspect -f '{{range .Config.Env}}{{println (index (split . "=") 0)}}{{end}}' "$name")
if printf '%s\n' "$keys" | grep -Eq 'TOKEN|PASSWORD|SECRET|CONTACT|DATABASE_URL'; then false; fi
if [ "$mode" = identity-only ]; then
  printf '%s\n' gateway_prestart_identity_verified
  exit 0
fi
stage=network_names
networks=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{println $k}}{{end}}' "$name" | bash "$DIR/normalize-network-names.sh")
[ "$networks" = "$(printf '%s\n' wallet-security-mailu-outbound wallet-security-notification | sort)" ]
stage=network_internal
[ "$(docker network inspect -f '{{.Internal}}' wallet-security-notification)" = true ]
[ "$(docker network inspect -f '{{.Internal}}' wallet-security-mailu-outbound)" = false ]
stage=network_members
[ "$(docker network inspect -f '{{len .Containers}}' wallet-security-notification)" = 1 ]
[ "$(docker network inspect -f '{{len .Containers}}' wallet-security-mailu-outbound)" = 1 ]
stage=resource_bounds
[ "$(docker inspect -f '{{.HostConfig.Memory}}' "$name")" = 67108864 ]
[ "$(docker inspect -f '{{.HostConfig.NanoCpus}}' "$name")" = 100000000 ]
[ "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$name")" = 16 ]
security=$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$name")
[[ "$security" == *'"no-new-privileges:true"'* || "$security" == *'"no-new-privileges"'* ]]
stage=worker_denial
worker=$(docker ps -q --filter label=com.docker.compose.project=qri1j8vhtwwb9akyxfiw73gc --filter label=com.docker.compose.service=worker)
[[ "$worker" =~ ^[0-9a-f]{12,64}$ ]]
[ "$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{println $k}}{{end}}' "$worker")" = qri1j8vhtwwb9akyxfiw73gc_private ]
docker exec "$worker" /bin/bash -c 'set -eu; test "$(id -u)" = 10001; if timeout 2 bash -c "exec 3<>/dev/tcp/167.233.253.175/587" >/dev/null 2>&1; then exit 1; fi' >/dev/null 2>&1
if [ "$mode" = topology-only ]; then
  printf '%s\n' gateway_topology_structural_guards_pass_not_delivery=true
  exit 0
fi
stage=tls_probe
docker run --rm --name wallet-security-mail-gateway-probe --network wallet-security-notification --read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 64m --cpus 0.1 --pids-limit 16 --log-driver none --entrypoint /bin/bash "$image" /app/preflight.sh
stage=receipt
[[ "$image_ref" =~ ^sha256:[a-f0-9]{64}$ && "$config_digest" =~ ^sha256:[a-f0-9]{64}$ ]]
printf 'mail_gateway_runtime_pass source_sha=%s running_image_ref=%s built_config_digest=%s uid=10001 ports=0 mounts=0 credentials=false networks=2 memory_bytes=67108864 nano_cpus=100000000 pids=16 nnp=true worker_direct_egress_denied=true\n' "$sha" "$image_ref" "$config_digest"
