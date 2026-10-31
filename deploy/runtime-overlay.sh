#!/bin/bash
# Operator start hook for a reviewed data-only hostname override. The JSON file
# contains a literal Coolify variable reference, never an expanded credential.
set -euo pipefail
app=${1:?application UUID required}
sha=${2:?exact source SHA required}
[[ "$app" =~ ^[a-z0-9]{20,32}$ && "$sha" =~ ^[0-9a-f]{40}$ ]]
image="wallet-security:$sha"
revision=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
test "$revision" = "$sha"
overlay=$(mktemp /tmp/wallet-security-overlay.XXXXXX)
trap 'unlink "$overlay"' EXIT
# Unique container DNS resolves only this deployment's private PostgreSQL.
printf '{"services":{"api":{"environment":{"DATABASE_URL":"postgresql://security_api:${DB_API_PASSWORD:?}@%s-postgres-1:5432/wallet_security"}}}}\n' "$app" > "$overlay"
docker compose --env-file .env -f compose.yml -f "$overlay" --project-directory "/data/coolify/applications/$app" -p "$app" up -d --no-build
printf 'RUNTIME_OVERLAY_PASS api_database_host=deployment_private_postgres image_source=%s\n' "$sha"
