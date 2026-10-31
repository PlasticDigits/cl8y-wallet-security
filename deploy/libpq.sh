# Translate our generated hex-password URL to libpq environment fields.
# PGDATABASE alone does not expand a URI in every PostgreSQL client.
case "${DATABASE_URL:-}" in
  postgresql://*:*@*:*/*) ;;
  *) printf 'invalid deployment database URL\n' >&2; exit 1 ;;
esac
db_authority=${DATABASE_URL#postgresql://}
db_identity=${db_authority%%@*}
db_endpoint=${db_authority#*@}
export PGUSER="${db_identity%%:*}" PGPASSWORD="${db_identity#*:}"
export PGHOST="${db_endpoint%%:*}"
db_port_path=${db_endpoint#*:}
export PGPORT="${db_port_path%%/*}" PGDATABASE="${db_port_path#*/}"
unset DATABASE_URL db_authority db_identity db_endpoint db_port_path
