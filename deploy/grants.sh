#!/bin/sh
set -eu
export PGDATABASE="$DATABASE_URL"
unset DATABASE_URL
exec psql -X -q -v ON_ERROR_STOP=1 -f /app/deploy/grants.sql
