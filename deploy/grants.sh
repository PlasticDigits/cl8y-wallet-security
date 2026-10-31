#!/bin/sh
set -eu
. /app/deploy/libpq.sh
exec psql -X -q -v ON_ERROR_STOP=1 -f /app/deploy/grants.sql
