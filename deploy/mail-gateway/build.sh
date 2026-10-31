#!/bin/bash
# Validate the exact image inputs even when Coolify strips .git from its checkout.
set -eu -o pipefail
sha=$1
[[ "$#" = 1 && "$sha" =~ ^[a-f0-9]{40}$ ]]
printf '%s\n' mail_gateway_build_hook_entered
context=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
expected=$(curl --proto =https -fsSm 8 "https://git.cl8y.com/code/cl8y-wallet-security/raw/commit/$sha/deploy/mail-gateway/image-inputs.sha256")
declare -A seen=()
while read -r hash file extra; do
  [[ "$hash" =~ ^[a-f0-9]{64}$ && -z "$extra" ]]
  case "$file" in Cargo.toml|Cargo.lock|Dockerfile|preflight.sh|src/main.rs) ;; *) exit 1;; esac
  [[ -z "${seen[$file]+present}" && -f "$context/$file" && ! -L "$context/$file" ]]
  seen[$file]=true
  actual=$(sha256sum "$context/$file")
  [[ "${actual%% *}" = "$hash" ]]
done <<< "$expected"
[[ "${#seen[@]}" = 5 ]]
printf '%s\n' mail_gateway_image_inputs_verified
timeout 45 docker build --build-arg SOURCE_SHA="$sha" -t "wallet-security-mail-gateway:$sha" "$context"
