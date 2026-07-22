#!/usr/bin/env bash
set -Eeuo pipefail

PG_RESTORE_BIN="${PG_RESTORE_BIN:-/usr/lib/postgresql/17/bin/pg_restore}"
PSQL_BIN="${PSQL_BIN:-/usr/lib/postgresql/17/bin/psql}"

if [[ "$#" -ne 2 ]]; then
    echo "Usage: $0 BACKUP_FILE TARGET_DATABASE_URL" >&2
    exit 64
fi

backup_file="$1"
target_url="$2"

if [[ ! -r "$backup_file" ]]; then
    echo "Backup is not readable: $backup_file" >&2
    exit 66
fi

if [[ ! -x "$PG_RESTORE_BIN" ]]; then
    echo "pg_restore is unavailable: $PG_RESTORE_BIN" >&2
    exit 69
fi

if [[ ! -x "$PSQL_BIN" ]]; then
    echo "psql is unavailable: $PSQL_BIN" >&2
    exit 69
fi

echo "Validating backup archive..."
"$PG_RESTORE_BIN" --list "$backup_file" >/dev/null

echo "Preparing PostgreSQL extensions..."

"$PSQL_BIN" \
    "$target_url" \
    --set=ON_ERROR_STOP=1 \
    --no-psqlrc <<'SQL'
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
SQL

echo "Restoring ShipIt public schema..."

"$PG_RESTORE_BIN" \
    --dbname="$target_url" \
    --schema=public \
    --no-owner \
    --no-privileges \
    --single-transaction \
    --verbose \
    "$backup_file"

echo "Restore completed"
