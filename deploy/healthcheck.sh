#!/bin/bash
set -euo pipefail
if [ "${PROCESS_MODE:-api}" = worker ]; then
  export PGDATABASE="$DATABASE_URL"
  unset DATABASE_URL
  result=$(psql -X -qAt -v ON_ERROR_STOP=1 <<'SQL'
\getenv expected SOURCE_SHA
SELECT EXISTS(SELECT 1 FROM worker_heartbeats WHERE name='notifications'
 AND source_sha=:'expected' AND last_seen>now()-interval '60 seconds');
SQL
)
  test "$result" = t
else
  exec 3<>/dev/tcp/127.0.0.1/8080
  printf 'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3
  head -n 1 <&3 | grep -q '200 OK'
fi
