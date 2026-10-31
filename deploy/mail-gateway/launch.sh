#!/bin/bash
set -eu -o pipefail
app=$1
sha=$2
[[ "$app" =~ ^[a-z0-9]{20,32}$ && "$app" != qri1j8vhtwwb9akyxfiw73gc && "$sha" =~ ^[a-f0-9]{40}$ ]]
timeout 30 docker compose --env-file .env -f deploy/mail-gateway/compose.yml --project-directory "/data/coolify/applications/$app/deploy/mail-gateway" --project-name "$app" up -d --no-build gateway
timeout 35 bash deploy/mail-gateway/runtime-check.sh "$sha"
