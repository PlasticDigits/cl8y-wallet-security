#!/bin/bash
# Runs only in the authorized deployment builder; never mounts Docker into a workload.
set -eu -o pipefail
exec 2>/dev/null
sha=$1
[[ "$sha" =~ ^[0-9a-f]{40}$ ]]
name=wallet-security-mail-gateway
image=wallet-security-mail-gateway:$sha
stage=identity
created=false
trap 'if [ "$created" = true ]; then docker rm wallet-security-mail-gateway-binding-probe >/dev/null 2>&1; fi' EXIT
trap 'printf "mail_gateway_runtime_failed stage=%s\n" "$stage"' ERR
[ "$(docker inspect -f '{{.Config.User}}' "$name")" = '10001:10001' ]
[ "$(docker inspect -f '{{.Config.Image}}' "$name")" = "$image" ]
[ "$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")" = "$sha" ]
[ "$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$name")" = "$sha" ]
# Bind actual running reference to a no-start create from the freshly built tag
# on this daemon. Daemons may expose a manifest ref or a config ID in .Image.
docker create --name wallet-security-mail-gateway-binding-probe --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --entrypoint /app/mail-gateway "$image" >/dev/null
created=true
image_ref=$(docker inspect -f '{{.Image}}' "$name")
[ "$image_ref" = "$(docker inspect -f '{{.Image}}' wallet-security-mail-gateway-binding-probe)" ]
[ "$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' wallet-security-mail-gateway-binding-probe)" = "$sha" ]
config_digest=$(docker image inspect -f '{{.Id}}' "$image")
docker rm wallet-security-mail-gateway-binding-probe >/dev/null
created=false
[ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ]
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
stage=networks
networks=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{println $k}}{{end}}' "$name" | sort)
[ "$networks" = "$(printf '%s\n' wallet-security-mailu-outbound wallet-security-notification | sort)" ]
[ "$(docker network inspect -f '{{.Internal}}' wallet-security-notification)" = true ]
[ "$(docker network inspect -f '{{.Internal}}' wallet-security-mailu-outbound)" = false ]
[ "$(docker network inspect -f '{{len .Containers}}' wallet-security-notification)" = 1 ]
[ "$(docker network inspect -f '{{len .Containers}}' wallet-security-mailu-outbound)" = 1 ]
stage=worker_denial
worker=$(docker ps -q --filter label=com.docker.compose.project=qri1j8vhtwwb9akyxfiw73gc --filter label=com.docker.compose.service=worker)
[[ "$worker" =~ ^[0-9a-f]{12,64}$ ]]
[ "$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{println $k}}{{end}}' "$worker")" = qri1j8vhtwwb9akyxfiw73gc_private ]
docker exec "$worker" /bin/bash -c 'set -eu; test "$(id -u)" = 10001; if timeout 2 bash -c "exec 3<>/dev/tcp/167.233.253.175/587" >/dev/null 2>&1; then exit 1; fi' >/dev/null 2>&1
stage=tls_probe
docker run --rm --name wallet-security-mail-gateway-probe --network wallet-security-notification --read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 64m --cpus 0.1 --pids-limit 16 --log-driver none --entrypoint /bin/bash "$image" /app/preflight.sh
stage=receipt
[[ "$image_ref" =~ ^sha256:[a-f0-9]{64}$ && "$config_digest" =~ ^sha256:[a-f0-9]{64}$ ]]
printf 'mail_gateway_runtime_pass source_sha=%s running_image_ref=%s built_config_digest=%s uid=10001 ports=0 mounts=0 credentials=false networks=2 worker_direct_egress_denied=true\n' "$sha" "$image_ref" "$config_digest"
