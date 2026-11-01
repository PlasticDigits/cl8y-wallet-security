#!/bin/bash
# One reviewed schema-6 rollout; secrets stay in Coolify's protected env file.
set -euo pipefail
exec 2>/dev/null
APP=qri1j8vhtwwb9akyxfiw73gc
SOURCE=4fbe03977337925f6185b393a8aa39437095b097
OLD=e44569e45b15dbee4b0347dff742f92bd85bedb2
MANIFEST=sha256:ff9dc660dabb80a426c4cd0f52e222277549756620d0cc457c4e05cc8c9ceb4d
CONFIG=sha256:296ada1e15c704943511af859d62d43922f7ce352d51b23adaafdc70c6d0a2ea
GATEWAY=643b1cc6f975dc11dbae9f3de7e8576b5922b502f3147ec6d076c7aea8902886
NET=wallet-security-notification
test "$#" = 3 && test "$1" = "$APP" && test "$2" = "$SOURCE"
# Compose must select exactly the image checked below, independent of old .env.
export SOURCE_SHA="$SOURCE"
mode=$3
api_ready=false
delivery_ready=false
sandbox=',"NOTIFICATION_SANDBOX_DESTINATIONS":"wallet-security-smoke@cl8y.com"'
case "$mode" in
  stage) ;;
  sandbox) api_ready=true; delivery_ready=true ;;
  production) api_ready=true; delivery_ready=true; sandbox='' ;;
  *) exit 1 ;;
esac
stage=preflight
overlay=$(mktemp /tmp/wallet-security-mail-overlay.XXXXXX)
transition=false
readc() { timeout 5 docker inspect --format "$1" "$2"; }
service_cid() {
  local found
  found=$(timeout 5 docker ps -a -q --no-trunc --filter "label=com.docker.compose.project=$APP" --filter "label=com.docker.compose.service=$1") || return 1
  [[ "$found" =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s' "$found"
}
optional_service_cid() {
  local found
  found=$(timeout 5 docker ps -a -q --no-trunc --filter "label=com.docker.compose.project=$APP" --filter "label=com.docker.compose.service=$1") || return 1
  test -z "$found" || [[ "$found" =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s' "$found"
}
owned_app() {
  test "$(readc '{{index .Config.Labels "com.docker.compose.project"}}' "$1")" = "$APP" || return 1
  local revision
  revision=$(readc '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$1") || return 1
  test "$revision" = "$OLD" || test "$revision" = "$SOURCE"
}
cleanup() {
  local rc=$?
  rm -f "$overlay"
  if test "$rc" != 0; then
    if test "$transition" = true; then
      # Do not restart an old worker after a possibly completed migration.
      local worker
      worker=$(service_cid worker) && owned_app "$worker" && timeout 35 docker stop --time 25 "$worker" >/dev/null || true
    fi
    printf 'mail_runtime_failed stage=%s legacy_worker_rollback=false\n' "$stage"
  fi
}
trap cleanup EXIT
image="wallet-security:$SOURCE"
stage=artifact_identity
test "$(timeout 5 docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")" = "$SOURCE"
actual=$(timeout 5 docker image inspect --format '{{.Id}}' "$image")
test "$actual" = "$MANIFEST" || test "$actual" = "$CONFIG"
stage=gateway_identity
test "$(readc '{{.State.Running}}' "$GATEWAY")" = true
test "$(readc '{{.Name}}' "$GATEWAY")" = /wallet-security-mail-gateway
test "$(readc '{{.Config.Image}}' "$GATEWAY")" = wallet-security-mail-gateway:44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5
test "$(readc '{{index .Config.Labels "com.docker.compose.project"}}' "$GATEWAY")" = y08cgj4rjem3ldgfmxb11nsp
test "$(readc '{{index .Config.Labels "com.cl8y.scope"}}' "$GATEWAY")" = wallet-security-mail-gateway
test "$(readc '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$GATEWAY")" = 44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5
test "$(timeout 5 docker network inspect --format '{{.Internal}}' "$NET")" = true
test "$(readc '{{with index .NetworkSettings.Networks "wallet-security-notification"}}{{.NetworkID}}{{end}}' "$GATEWAY")" = e1f3b89f1f7b590b7fa34def87b39521927b5b28d251189734ebd019b84081b4
stage=persistent_volume_identity
test "$(timeout 5 docker volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "${APP}_pgdata")" = "$APP"
test "$(timeout 5 docker volume inspect --format '{{index .Labels "com.docker.compose.volume"}}' "${APP}_pgdata")" = pgdata
stage=existing_service_inventory
api=$(optional_service_cid api); worker=$(optional_service_cid worker)
test -z "$api" || owned_app "$api"
test -z "$worker" || owned_app "$worker"
members=$(timeout 5 docker network inspect --format '{{len .Containers}}' "$NET")
if test "$members" = 2; then
  # Rerunning the same release/mode may only find its own upgraded worker.
  test "$(readc '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$worker")" = "$SOURCE"
  test "$(timeout 5 docker network inspect --format "{{with index .Containers \"$worker\"}}owned{{end}}" "$NET")" = owned
else test "$members" = 1
fi
# This file contains literal variable references, never expanded secret values.
printf '{"services":{"api":{"environment":{"DATABASE_URL":"postgresql://security_api:${DB_API_PASSWORD:?}@%s-postgres-1:5432/wallet_security","EMAIL_PROVIDER":"smtp","MAILU_EMAIL_ENABLED":"%s"}},"worker":{"networks":["private","notification"],"environment":{"EMAIL_PROVIDER":"smtp","MAILU_SMTP_TOKEN":"${MAILU_SMTP_TOKEN:?}","MAILU_DELIVERY_ENABLED":"%s"%s}}},"networks":{"notification":{"external":true,"name":"wallet-security-notification"}}}\n' "$APP" "$api_ready" "$delivery_ready" "$sandbox" > "$overlay"
compose=(docker compose --env-file .env -f compose.yml -f "$overlay" --project-directory "/data/coolify/applications/$APP" -p "$APP")
stage=compose_validation
timeout 15 "${compose[@]}" config --quiet
stage=fence
transition=true
for cid in "$worker" "$api"; do
  if test -n "$cid"; then
    timeout 35 docker stop --time 25 "$cid" >/dev/null
    test "$(readc '{{.State.Running}}' "$cid")" = false
  fi
done
stage=migrate_and_start
# Do not launch an old generic restore job against a pre-migration dump.
timeout 120 "${compose[@]}" up -d --no-build api worker backup >/dev/null
stage=runtime_boundary
api=$(service_cid api); worker=$(service_cid worker); postgres=$(service_cid postgres)
private=$(timeout 5 docker network inspect --format '{{.Id}}' "${APP}_private")
test "$(timeout 5 docker network inspect --format '{{.Internal}}' "$private")" = true
test "$(readc "{{with index .NetworkSettings.Networks \"${APP}_private\"}}{{.NetworkID}}{{end}}" "$postgres")" = "$private"
for cid in "$api" "$worker"; do
  owned_app "$cid"
  test "$(readc '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$cid")" = "$SOURCE"
  test "$(readc '{{.Config.User}}' "$cid")" = 10001:10001
  test "$(readc '{{.HostConfig.ReadonlyRootfs}}' "$cid")" = true
done
test "$(readc '{{len .NetworkSettings.Networks}}' "$worker")" = 2
test "$(readc '{{range .Config.Env}}{{if eq (index (split . "=") 0) "MAILU_SMTP_TOKEN"}}forbidden{{end}}{{end}}' "$api")" = ''
test "$(readc "{{with index .NetworkSettings.Networks \"${APP}_private\"}}{{.NetworkID}}{{end}}" "$worker")" = "$private"
test "$(readc '{{with index .NetworkSettings.Networks "coolify"}}attached{{end}}' "$worker")" = ''
test "$(readc '{{with index .NetworkSettings.Networks "wallet-security-mailu-outbound"}}attached{{end}}' "$worker")" = ''
for cid in "$api" "$postgres"; do
  test "$(readc '{{with index .NetworkSettings.Networks "wallet-security-notification"}}attached{{end}}' "$cid")" = ''
done
test "$(readc '{{with index .NetworkSettings.Networks "wallet-security-notification"}}{{.NetworkID}}{{end}}' "$worker")" = e1f3b89f1f7b590b7fa34def87b39521927b5b28d251189734ebd019b84081b4
test "$(timeout 5 docker network inspect --format '{{len .Containers}}' "$NET")" = 2
timeout 5 docker exec "$worker" /bin/bash -c 'while read -r iface destination rest; do test "$destination" != 00000000 || exit 1; done </proc/net/route'
gateway_ip=$(readc '{{with index .NetworkSettings.Networks "wallet-security-notification"}}{{.IPAddress}}{{end}}' "$GATEWAY")
test -n "$gateway_ip"
answers=$(timeout 5 docker exec "$worker" getent ahostsv4 mail.cl8y.com)
test -n "$answers"
while read -r address rest; do test "$address" = "$gateway_ip"; done <<< "$answers"
printf 'mail_runtime_started source_sha=%s migration_target=6 mode=%s worker_networks=2 api_pg_notification_network=false alias_fixed_gateway=true\n' "$SOURCE" "$mode"
