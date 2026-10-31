#!/bin/bash
# Immutable, credential-free builder hook; only the validated public SHA is an argument.
set -eu -o pipefail
sha=$1
[[ "$#" = 1 && "$sha" =~ ^[a-f0-9]{40}$ ]]
root=$(git rev-parse --show-toplevel)
[ "$(git -C "$root" rev-parse HEAD)" = "$sha" ]
timeout 50 docker build --build-arg SOURCE_SHA="$sha" -t "wallet-security-mail-gateway:$sha" "$root/deploy/mail-gateway"
