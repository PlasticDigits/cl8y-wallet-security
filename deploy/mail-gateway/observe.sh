#!/bin/bash
# Fixed two-resource, read-only daemon observer. NEVER prints Env values/filesystem data.
# Always exits nonzero so the application deployment cannot reach service changes.
set -eu -o pipefail
exec 2>/dev/null
trap 'printf "%s\n" observer_fixed_metadata_failed' ERR
[ "$#" = 0 ]
APP=y08cgj4rjem3ldgfmxb11nsp
GATEWAY=wallet-security-mail-gateway
SEALER=seal-3nolvrgyhudkv3itihuyuim9
safe() { [[ "$1" =~ ^[A-Za-z0-9_.:/,=-]*$ && ${#1} -le 256 ]]; }
num() { [[ "$1" =~ ^-?[0-9]{1,20}$ ]]; }
hexid() { [[ "$1" =~ ^[a-f0-9]{64}$ ]]; }
declare -A networks=()
gateway_id=''
container() {
  local role=$1 name=$2 id image user running mode memory cpu pids ro caps security nnp names item mounts mname target rw type
  if ! id=$(docker inspect -f '{{.Id}}' "$name"); then
    printf '{"record":"container","role":"%s","present":false}\n' "$role"
    return
  fi
  hexid "$id"
  image=$(docker inspect -f '{{.Image}}' "$name"); [[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]]
  if [ "$role" = gateway ]; then
    [ "$(docker inspect -f '{{index .Config.Labels "com.cl8y.scope"}}' "$name")" = wallet-security-mail-gateway ]
    [ "$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$name")" = 44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5 ]
    gateway_id=$id
  fi
  user=$(docker inspect -f '{{.Config.User}}' "$name"); safe "$user"
  running=$(docker inspect -f '{{.State.Running}}' "$name"); [[ "$running" = true || "$running" = false ]]
  mode=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$name"); safe "$mode"
  memory=$(docker inspect -f '{{.HostConfig.Memory}}' "$name"); num "$memory"
  cpu=$(docker inspect -f '{{.HostConfig.NanoCpus}}' "$name"); num "$cpu"
  pids=$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$name"); [[ "$pids" = '<nil>' ]] && pids=null; [[ "$pids" = null ]] || num "$pids"
  ro=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$name"); [[ "$ro" = true || "$ro" = false ]]
  caps=$(docker inspect -f '{{join .HostConfig.CapDrop ","}}' "$name"); safe "$caps"
  security=$(docker inspect -f '{{join .HostConfig.SecurityOpt ","}}' "$name"); safe "$security"
  nnp=false; [[ "$security" == *no-new-privileges* ]] && nnp=true
  mounts=$(docker inspect -f '{{len .Mounts}}' "$name"); num "$mounts"
  printf '{"record":"container","role":"%s","present":true,"id":"%s","image_ref":"%s","user":"%s","running":%s,"network_mode":"%s","memory":%s,"nano_cpus":%s,"pids_limit":%s,"read_only":%s,"cap_drop_csv":"%s","security_opt_csv":"%s","nnp":%s,"mount_count":%s}\n' "$role" "$id" "$image" "$user" "$running" "$mode" "$memory" "$cpu" "$pids" "$ro" "$caps" "$security" "$nnp" "$mounts"
  while IFS='|' read -r type mname target rw; do
    [ -n "$type" ] || continue
    safe "$type"; safe "$mname"; safe "$target"; [[ "$rw" = true || "$rw" = false ]]
    printf '{"record":"mount","role":"%s","type":"%s","name":"%s","destination":"%s","rw":%s}\n' "$role" "$type" "$mname" "$target" "$rw"
  done < <(docker inspect -f '{{range .Mounts}}{{printf "%s|%s|%s|%t\n" .Type .Name .Destination .RW}}{{end}}' "$name")
  # Values never leave the Docker template; only validated variable names are emitted.
  while IFS= read -r item; do
    [ -n "$item" ] || continue
    [[ "$item" =~ ^[A-Za-z_][A-Za-z0-9_]{0,127}$ ]]
    printf '{"record":"env_name","role":"%s","name":"%s"}\n' "$role" "$item"
  done < <(docker inspect -f '{{range .Config.Env}}{{println (index (split . "=") 0)}}{{end}}' "$name")
  if [ "$role" = gateway ]; then
    local net nid aliases
    while IFS='|' read -r net nid aliases; do
      [ -n "$net" ] || continue
      safe "$net"; safe "$aliases"
      if [ -n "$nid" ]; then hexid "$nid"; networks[$nid]=true; fi
      printf '{"record":"gateway_attachment","name":"%s","id":"%s","aliases_csv":"%s"}\n' "$net" "$nid" "$aliases"
    done < <(docker inspect -f '{{range $name,$net := .NetworkSettings.Networks}}{{printf "%s|%s|%s\n" $name $net.NetworkID (join $net.Aliases ",")}}{{end}}' "$name")
  fi
}
container gateway "$GATEWAY"
container sealer "$SEALER"
# Also retain owned network evidence if the stop action removed the gateway.
while IFS= read -r id; do [ -z "$id" ] || { hexid "$id"; networks[$id]=true; }; done < <(docker network ls --no-trunc -q --filter label=com.docker.compose.project="$APP")
for expected in wallet-security-notification wallet-security-mailu-outbound "$APP"; do
  if id=$(docker network inspect -f '{{.Id}}' "$expected"); then hexid "$id"; networks[$id]=true; fi
done
for id in "${!networks[@]}"; do
  name=$(docker network inspect -f '{{.Name}}' "$id"); safe "$name"
  driver=$(docker network inspect -f '{{.Driver}}' "$id"); safe "$driver"
  internal=$(docker network inspect -f '{{.Internal}}' "$id"); [[ "$internal" = true || "$internal" = false ]]
  count=$(docker network inspect -f '{{len .Containers}}' "$id"); num "$count"
  printf '{"record":"network","name":"%s","id":"%s","driver":"%s","internal":%s,"members":%s}\n' "$name" "$id" "$driver" "$internal" "$count"
  while IFS='|' read -r cid cname; do
    [ -n "$cid" ] || continue
    hexid "$cid"; safe "$cname"
    printf '{"record":"network_member","network_id":"%s","id":"%s","name":"%s"}\n' "$id" "$cid" "$cname"
  done < <(docker network inspect -f '{{range $id,$item := .Containers}}{{printf "%s|%s\n" $id $item.Name}}{{end}}' "$id")
done
# Finite, project-filtered event metadata can help reconstruct a removed gateway.
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
events=$(timeout 5 docker events --since 2h --until "$now" --filter type=network --filter label=com.docker.compose.project="$APP" --format '{{.Action}}|{{.Actor.ID}}|{{index .Actor.Attributes "name"}}|{{index .Actor.Attributes "container"}}|{{.Time}}')
while IFS='|' read -r action nid name cid stamp; do
  [ -n "$action" ] || continue
  case "$action" in create|connect|disconnect|destroy) ;; *) continue;; esac
  hexid "$nid"; safe "$name"; num "$stamp"; [ -z "$cid" ] || hexid "$cid"
  printf '{"record":"owned_network_event","action":"%s","network_id":"%s","name":"%s","container_id":"%s","time":%s}\n' "$action" "$nid" "$name" "$cid" "$stamp"
done <<< "$events"
printf '%s\n' observer_read_only_complete_service_changes=false
exit 1
