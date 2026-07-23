#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

RESTIC_ENV_FILE="${RESTIC_ENV_FILE:-/etc/shipit/restic.env}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/shipit/postgres}"
MAX_BACKUP_AGE_SECONDS="${MAX_BACKUP_AGE_SECONDS:-129600}"
LOCK_FILE="${OFFSITE_LOCK_FILE:-/run/lock/shipit-db-offsite.lock}"
PG_RESTORE="${PG_RESTORE:-/usr/lib/postgresql/17/bin/pg_restore}"
RESTIC_HOST="${RESTIC_HOST:-$(hostname -s)}"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

for command in restic flock sha256sum stat find sort hostname; do
    command -v "$command" >/dev/null 2>&1 ||
        fail "required command is unavailable: $command"
done

[[ -x "$PG_RESTORE" ]] ||
    fail "pg_restore is unavailable: $PG_RESTORE"

[[ -r "$RESTIC_ENV_FILE" ]] ||
    fail "restic environment file is unreadable: $RESTIC_ENV_FILE"

set -a
# shellcheck disable=SC1090
source "$RESTIC_ENV_FILE"
set +a

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is required}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE is required}"
: "${RESTIC_CACHE_DIR:?RESTIC_CACHE_DIR is required}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"
: "${AWS_DEFAULT_REGION:?AWS_DEFAULT_REGION is required}"

[[ "$MAX_BACKUP_AGE_SECONDS" =~ ^[0-9]+$ ]] ||
    fail "MAX_BACKUP_AGE_SECONDS must be an integer"

install -d -m 0700 "$RESTIC_CACHE_DIR"

exec 9>"$LOCK_FILE"

if ! flock -n 9; then
    echo "Another ShipIt off-site operation is already running"
    exit 75
fi

mapfile -t backup_names < <(
    find "$BACKUP_DIR" \
        -maxdepth 1 \
        -type f \
        -name 'shipit-*.dump' \
        -printf '%f\n' |
    LC_ALL=C sort
)

((${#backup_names[@]} > 0)) ||
    fail "no PostgreSQL dumps found in $BACKUP_DIR"

latest_index=$((${#backup_names[@]} - 1))
latest_dump="${BACKUP_DIR}/${backup_names[$latest_index]}"
latest_checksum="${latest_dump}.sha256"

[[ -r "$latest_dump" ]] ||
    fail "latest dump is unreadable: $latest_dump"

[[ -r "$latest_checksum" ]] ||
    fail "checksum file is missing: $latest_checksum"

now="$(date +%s)"
dump_mtime="$(stat -c '%Y' "$latest_dump")"

if ((dump_mtime > now + 300)); then
    fail "dump modification time is unexpectedly in the future"
fi

dump_age=$((now - dump_mtime))

if ((dump_age > MAX_BACKUP_AGE_SECONDS)); then
    fail "latest dump is stale: age=${dump_age}s limit=${MAX_BACKUP_AGE_SECONDS}s"
fi

echo "Selected dump: $latest_dump"
echo "Dump age: ${dump_age}s"

if ! sha256sum --check --status "$latest_checksum"; then
    fail "local dump checksum validation failed"
fi

echo "Local checksum: OK"

if ! "$PG_RESTORE" --list "$latest_dump" >/dev/null; then
    fail "PostgreSQL archive validation failed"
fi

echo "PostgreSQL archive: OK"
echo "Uploading encrypted snapshot to off-site repository..."

restic backup \
    --host "$RESTIC_HOST" \
    --group-by host,tags \
    --tag shipit-postgres \
    --tag production \
    "$latest_dump" \
    "$latest_checksum"

echo "Off-site backup completed: $latest_dump"
