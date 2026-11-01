#!/bin/bash
# Control-plane BUILD helper only. Fixed ephemeral exporter selector; never
# print ENV values/files/data or reach the deployment's service-stop phase.
set -euo pipefail
resource=${1:?export service UUID required}
[[ "$resource" =~ ^[a-z0-9]{20,32}$ ]]
container="export-$resource"
configured_image=$(docker inspect -f '{{.Config.Image}}' "$container")
[[ "$configured_image" =~ ^git\.cl8y\.com/code/cl8y-wallet-security-cipher-export@sha256:[0-9a-f]{64}$ ]]
image=$(docker inspect -f '{{.Image}}' "$container")
inspected_id=$(docker image inspect -f '{{.Id}}' "$configured_image")
source=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$configured_image")
[[ "$image" =~ ^sha256:[0-9a-f]{64}$ && "$inspected_id" =~ ^sha256:[0-9a-f]{64}$ && "$source" =~ ^[0-9a-f]{40}$ ]]
# A registry manifest and its image config are separate reviewed identities.
# Some daemon APIs report the manifest in container .Image; emit both without
# relabeling the observed field as a config digest.
printf 'WG_OBS_IMAGE reference=%s actual=%s inspected_id=%s source=%s\n' "${configured_image##*@}" "$image" "$inspected_id" "$source"
docker inspect -f 'WG_OBS_HOST user={{.Config.User}} running={{.State.Running}} network={{.HostConfig.NetworkMode}} memory={{.HostConfig.Memory}} cpu={{.HostConfig.NanoCpus}} pids={{.HostConfig.PidsLimit}} readonly={{.HostConfig.ReadonlyRootfs}} ports={{len .HostConfig.PortBindings}}' "$container"
docker inspect -f '{{range .Mounts}}{{println "WG_OBS_MOUNT" .Type .Name .Destination .RW}}{{end}}' "$container"
docker inspect -f '{{range .HostConfig.CapDrop}}{{println "WG_OBS_CAPDROP" .}}{{end}}{{range .HostConfig.SecurityOpt}}{{println "WG_OBS_SECURITY" .}}{{end}}' "$container"
printf 'WG_OBS_ENV_NAMES_BEGIN\n'
docker inspect -f '{{range .Config.Env}}{{index (split . "=") 0}}{{println}}{{end}}' "$container" | sort
printf 'WG_OBS_ENV_NAMES_END\n'
# Observe only LISTEN sockets owned by this container's PID1. Host network does
# not justify publishing other processes' socket identities or address lists.
docker exec "$container" /bin/bash -ec 'for fd in /proc/1/fd/*; do target=$(readlink "$fd") || continue; if [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]]; then inode=${BASH_REMATCH[1]}; awk -v inode="$inode" '\''$10==inode && $4=="0A" {print "WG_OBS_LISTEN",$2}'\'' /proc/net/tcp /proc/net/tcp6; fi; done'
printf 'WG_OBS_COMPLETE read_only=true\n'
exit 1
