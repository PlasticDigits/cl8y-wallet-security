#!/bin/bash
set -euo pipefail
umask 077
export PGDATABASE="$DATABASE_URL"
unset DATABASE_URL
mkdir -p /backups
while true; do
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  file="/backups/wallet-security-$stamp.dump"
  timeout 120 pg_dump --format=custom --no-owner --no-acl --file="$file.partial"
  pg_restore --list "$file.partial" >/dev/null
  mv "$file.partial" "$file"
  sha256sum "$file" >"$file.sha256"
  find /backups -maxdepth 1 -type f -name 'wallet-security-*.dump*' -mtime +6 -delete
  printf 'backup_complete utc=%s\n' "$stamp"
  [ "${BACKUP_ONCE:-false}" = true ] && exit 0
  sleep 86400
done
