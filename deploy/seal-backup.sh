#!/bin/bash
# No private age identity, DB password, contact key, or S3 credential is needed.
set -euo pipefail
umask 077
[[ "${AGE_PUBLIC_RECIPIENT:-}" =~ ^age1[0-9a-z]+$ ]]
[[ "${MAX_DUMP_BYTES:-268435456}" =~ ^[0-9]+$ ]]
interval=${SEAL_INTERVAL_SECONDS:-300}
[[ "$interval" =~ ^[0-9]+$ ]] && [ "$interval" -ge 60 ] && [ "$interval" -le 86400 ]
stop_requested=false
trap 'stop_requested=true' TERM INT HUP
while true; do
  [ "$stop_requested" = false ] || exit 0
  dump=$(find /backups -maxdepth 1 -type f -name 'wallet-security-*.dump' | sort | tail -1)
  if [ -n "$dump" ]; then
    name=${dump##*/}
    [[ "$name" =~ ^wallet-security-[0-9]{8}T[0-9]{6}Z\.dump$ ]]
    test "$(stat -c '%s' "$dump")" -le "${MAX_DUMP_BYTES:-268435456}"
    timeout 15 sha256sum --check --status "$dump.sha256"
    timeout 15 pg_restore --list "$dump" >/dev/null
    [ "$stop_requested" = false ] || exit 0
    output="/encrypted/$name.age"
    if [ ! -f "$output" ] || [ ! -f "$output.sha256" ] || ! sha256sum --check --status "$output.sha256"; then
      partial="$output.partial"
      # A killed writer can leave a partial file or a complete file without its
      # checksum. Rebuild only that owned ciphertext from the verified input.
      test ! -L "$partial"
      test ! -f "$partial" || unlink "$partial"
      trap 'test ! -f "${partial:-/nonexistent}" || unlink "$partial"' EXIT
      timeout 120 age -r "$AGE_PUBLIC_RECIPIENT" -o "$partial" "$dump" 2>/dev/null
      mv "$partial" "$output"
      timeout 15 sha256sum "$output" > "$output.sha256"
      trap - EXIT
    fi
    timeout 15 sha256sum --check --status "$output.sha256"
    # Publish only the latest complete ciphertext. Outer offhost retention is
    # five days; the controller rejects source dumps older than 25 hours.
    mapfile -t archives < <(find /encrypted -maxdepth 1 -type f -name 'wallet-security-*.dump.age' | sort -r)
    for ((i=1; i<${#archives[@]}; i++)); do
      old=${archives[$i]}
      [[ "${old##*/}" =~ ^wallet-security-[0-9]{8}T[0-9]{6}Z\.dump\.age$ ]]
      unlink "$old"
      test ! -f "$old.sha256" || unlink "$old.sha256"
    done
    printf 'sealed_backup_complete dump=%s cipher_sha256=%s\n' "$name" "$(sha256sum "$output" | cut -d' ' -f1)"
  fi
  [ "${SEAL_ONCE:-false}" != true ] || exit 0
  [ "$stop_requested" = false ] || exit 0
  sleep "$interval" &
  wait "$!" || true
done
