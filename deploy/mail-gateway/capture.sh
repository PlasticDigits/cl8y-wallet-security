#!/bin/bash
# Only the fixed reproduction gateway; no other workload or Env is inspected.
set -eu -o pipefail
exec 2>/dev/null
trap 'printf "%s\n" gateway_topology_capture_failed' ERR
[ "$#" = 0 ]
name=wallet-security-mail-gateway
id=$(docker inspect -f '{{.Id}}' "$name"); [[ "$id" =~ ^[a-f0-9]{64}$ ]]
running=$(docker inspect -f '{{.State.Running}}' "$id"); [[ "$running" = true || "$running" = false ]]
printf '{"record":"gateway_capture_state","id":"%s","running":%s}\n' "$id" "$running"
self_id=$(hostname); [[ "$self_id" =~ ^[a-f0-9]{12,64}$ ]] || self_id=''
safe() { [[ "$1" =~ ^[A-Za-z0-9_.:/,=-]*$ && ${#1} -le 256 ]]; }
while IFS='|' read -r net nid aliases; do
  [ -n "$net" ] || continue
  safe "$net"; [[ "$nid" =~ ^[a-f0-9]{64}$ ]]; safe "$aliases"
  printf '{"record":"gateway_attachment","name":"%s","id":"%s","aliases_csv":"%s"}\n' "$net" "$nid" "$aliases"
  driver=$(docker network inspect -f '{{.Driver}}' "$nid"); safe "$driver"
  internal=$(docker network inspect -f '{{.Internal}}' "$nid"); [[ "$internal" = true || "$internal" = false ]]
  count=$(docker network inspect -f '{{len .Containers}}' "$nid"); [[ "$count" =~ ^[0-9]{1,10}$ ]]
  printf '{"record":"network","name":"%s","id":"%s","driver":"%s","internal":%s,"members":%s}\n' "$net" "$nid" "$driver" "$internal" "$count"
  other=0; self_helper=0
  while IFS='|' read -r cid cname; do
    [ -n "$cid" ] || continue
    [[ "$cid" =~ ^[a-f0-9]{64}$ ]]
    if [ "$cid" = "$id" ]; then kind=gateway; cname=$name
    elif [ "$cname" = coolify-proxy ]; then kind=managed_proxy
    elif [ -n "$self_id" ] && [[ "$cid" == "$self_id"* ]]; then self_helper=$((self_helper+1)); continue
    else other=$((other+1)); continue
    fi
    printf '{"record":"network_member","network_id":"%s","id":"%s","name":"%s","member_kind":"%s"}\n' "$nid" "$cid" "$cname" "$kind"
  done < <(docker network inspect -f '{{range $id,$item := .Containers}}{{printf "%s|%s\n" $id $item.Name}}{{end}}' "$nid")
  printf '{"record":"network_redacted_members","network_id":"%s","self_observer_helpers":%s,"other_members":%s}\n' "$nid" "$self_helper" "$other"
done < <(docker inspect -f '{{range $name,$net := .NetworkSettings.Networks}}{{printf "%s|%s|%s\n" $name $net.NetworkID (join $net.Aliases ",")}}{{end}}' "$id")
running=$(docker inspect -f '{{.State.Running}}' "$id"); [[ "$running" = true || "$running" = false ]]
printf 'gateway_topology_capture_complete running=%s\n' "$running"
