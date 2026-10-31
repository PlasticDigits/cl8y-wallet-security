#!/bin/bash
# No private age identity, DB password, contact key, or S3 credential is needed.
set -euo pipefail
umask 077
pause=/tmp/wallet-security-seal.pause
paused=/tmp/wallet-security-seal.paused

check_age() {
  local name=$1 stamp epoch now age
  [[ "$name" =~ ^wallet-security-([0-9]{8}T[0-9]{6}Z)\.dump$ ]]
  stamp=${BASH_REMATCH[1]}
  epoch=$(date -u -d "${stamp:0:4}-${stamp:4:2}-${stamp:6:2}T${stamp:9:2}:${stamp:11:2}:${stamp:13:2}Z" +%s)
  now=$(date -u +%s); age=$((now-epoch))
  [ "$age" -ge -60 ] && [ "$age" -le 90000 ]
}

check_complete() {
  local files=() all=() cipher name hash header
  shopt -s nullglob
  files=(/encrypted/wallet-security-*.dump.age)
  all=(/encrypted/*)
  [ "${#files[@]}" = 1 ] && [ "${#all[@]}" = 2 ]
  cipher=${files[0]}; name=${cipher##*/}; name=${name%.age}
  check_age "$name"
  [ -f "$cipher" ] && [ ! -L "$cipher" ] && [ -f "$cipher.sha256" ] && [ ! -L "$cipher.sha256" ]
  timeout 15 sha256sum --check --status "$cipher.sha256"
  header=$(head -c 22 "$cipher")
  [ "$header" = age-encryption.org/v1 ]
  hash=$(timeout 15 sha256sum "$cipher" | cut -d' ' -f1)
  printf 'sealed_backup_ready dump=%s cipher_sha256=%s\n' "$name" "$hash"
}

case "${1:-run}" in
  check) check_complete; exit 0 ;;
  pause)
    : > "$pause"
    deadline=$((SECONDS+180))
    until [ -f "$paused" ]; do
      [ "$SECONDS" -lt "$deadline" ] || exit 1
      sleep 1
    done
    check_complete
    printf 'sealed_backup_paused completed_pair=true\n'
    exit 0 ;;
  resume)
    test ! -f "$pause" || unlink "$pause"
    test ! -f "$paused" || unlink "$paused"
    printf 'sealed_backup_resumed\n'
    exit 0 ;;
  run) ;;
  *) exit 1 ;;
esac

[[ "${AGE_PUBLIC_RECIPIENT:-}" =~ ^age1[0-9a-z]+$ ]]
[[ "${MAX_DUMP_BYTES:-268435456}" =~ ^[0-9]+$ ]]
interval=${SEAL_INTERVAL_SECONDS:-300}
[[ "$interval" =~ ^[0-9]+$ ]] && [ "$interval" -ge 60 ] && [ "$interval" -le 86400 ]
stop_requested=false
trap 'stop_requested=true' TERM INT HUP
while true; do
  [ "$stop_requested" = false ] || exit 0
  if [ -f "$pause" ]; then
    : > "$paused"
    sleep 1 &
    wait "$!" || true
    continue
  fi
  test ! -f "$paused" || unlink "$paused"
  dump=$(find /backups -maxdepth 1 -type f -name 'wallet-security-*.dump' | sort | tail -1)
  if [ -n "$dump" ]; then
    name=${dump##*/}
    check_age "$name"
    test "$(stat -c '%s' "$dump")" -le "${MAX_DUMP_BYTES:-268435456}"
    timeout 15 sha256sum --check --status "$dump.sha256"
    timeout 15 pg_restore --list "$dump" >/dev/null
    [ "$stop_requested" = false ] || exit 0
    output="/encrypted/$name.age"
    if [ ! -f "$output" ] || [ ! -f "$output.sha256" ] || ! timeout 15 sha256sum --check --status "$output.sha256"; then
      partial="$output.partial"
      test ! -L "$partial"
      test ! -f "$partial" || unlink "$partial"
      trap 'test ! -f "${partial:-/nonexistent}" || unlink "$partial"' EXIT
      timeout 120 age -r "$AGE_PUBLIC_RECIPIENT" -o "$partial" "$dump" 2>/dev/null
      mv "$partial" "$output"
      timeout 15 sha256sum "$output" > "$output.sha256"
      trap - EXIT
    fi
    timeout 15 sha256sum --check --status "$output.sha256"
    # Exactly one inner dump avoids nested retention amplification.
    mapfile -t archives < <(find /encrypted -maxdepth 1 -type f -name 'wallet-security-*.dump.age' | sort -r)
    for ((i=1; i<${#archives[@]}; i++)); do
      old=${archives[$i]}
      [[ "${old##*/}" =~ ^wallet-security-[0-9]{8}T[0-9]{6}Z\.dump\.age$ ]]
      unlink "$old"
      test ! -f "$old.sha256" || unlink "$old.sha256"
    done
    check_complete
    printf 'sealed_backup_complete dump=%s cipher_sha256=%s\n' "$name" "$(timeout 15 sha256sum "$output" | cut -d' ' -f1)"
  fi
  [ "${SEAL_ONCE:-false}" != true ] || exit 0
  for ((elapsed=0; elapsed<interval; elapsed+=5)); do
    [ "$stop_requested" = false ] || exit 0
    test ! -f "$pause" || break
    sleep 5 &
    wait "$!" || true
  done
done
