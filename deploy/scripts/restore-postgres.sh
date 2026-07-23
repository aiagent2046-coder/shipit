#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <backup.dump> <target-database-url>" >&2
    exit 64
fi

backup="$1"
target_url="$2"

PG_RESTORE="/usr/lib/postgresql/17/bin/pg_restore"

[[ -f "$backup" ]] || {
    echo "Backup not found: $backup" >&2
    exit 66
}

if [[ -n "${DATABASE_URL:-}" && "$target_url" == "$DATABASE_URL" ]]; then
    if [[ "${ALLOW_PRODUCTION_RESTORE:-}" != "YES" ]]; then
        echo "Refusing to restore over production DATABASE_URL." >&2
        echo "Set ALLOW_PRODUCTION_RESTORE=YES only during an approved incident." >&2
        exit 77
    fi
fi

"$PG_RESTORE" --list "$backup" >/dev/null

"$PG_RESTORE" \
    --dbname="$target_url" \
    --clean \
    --if-exists \
    --no-owner \
    --no-privileges \
    "$backup"

echo "Restore completed"
