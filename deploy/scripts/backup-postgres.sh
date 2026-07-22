#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

: "${DATABASE_URL:?DATABASE_URL is required}"

BACKUP_DIR="${BACKUP_DIR:-/var/backups/shipit/postgres}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"

PG_DUMP="/usr/lib/postgresql/17/bin/pg_dump"
PG_RESTORE="/usr/lib/postgresql/17/bin/pg_restore"

[[ -x "$PG_DUMP" ]] || {
    echo "PostgreSQL 17 pg_dump not found" >&2
    exit 69
}

install -d -m 0700 "$BACKUP_DIR"

timestamp="$(date -u +'%Y%m%dT%H%M%SZ')"
partial="${BACKUP_DIR}/shipit-${timestamp}.dump.partial"
destination="${BACKUP_DIR}/shipit-${timestamp}.dump"

cleanup() {
    rm -f "$partial"
}
trap cleanup EXIT

"$PG_DUMP" \
    --dbname="$DATABASE_URL" \
    --format=custom \
    --compress=9 \
    --no-owner \
    --no-privileges \
    --file="$partial"

"$PG_RESTORE" --list "$partial" >/dev/null

mv "$partial" "$destination"
sha256sum "$destination" > "${destination}.sha256"

find "$BACKUP_DIR" \
    -type f \
    -mtime "+${BACKUP_KEEP_DAYS}" \
    \( -name '*.dump' -o -name '*.sha256' \) \
    -delete

echo "Backup created: $destination"
