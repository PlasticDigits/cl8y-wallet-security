#!/bin/bash
set -euo pipefail
# Runs only for a fresh dedicated PGDATA. Never turn on shell/SQL tracing.
psql -X --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v ON_ERROR_STOP=1 <<'SQL'
\getenv migrator_password DB_MIGRATOR_PASSWORD
\getenv api_password DB_API_PASSWORD
\getenv worker_password DB_WORKER_PASSWORD
\getenv backup_password DB_BACKUP_PASSWORD
CREATE ROLE security_migrator LOGIN PASSWORD :'migrator_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_api LOGIN PASSWORD :'api_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_worker LOGIN PASSWORD :'worker_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_backup LOGIN PASSWORD :'backup_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
REVOKE ALL ON DATABASE wallet_security FROM PUBLIC;
GRANT CONNECT ON DATABASE wallet_security TO security_migrator,security_api,security_worker,security_backup;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO security_migrator;
SQL
