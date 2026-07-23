#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

RESTIC_ENV_FILE="${RESTIC_ENV_FILE:-/etc/shipit/restic.env}"
LOCK_FILE="${OFFSITE_LOCK_FILE:-/run/lock/shipit-db-offsite.lock}"
RESTIC_HOST="${RESTIC_HOST:-$(hostname -s)}"

RESTIC_KEEP_LAST="${RESTIC_KEEP_LAST:-3}"
RESTIC_KEEP_DAILY="${RESTIC_KEEP_DAILY:-14}"
RESTIC_KEEP_WEEKLY="${RESTIC_KEEP_WEEKLY:-8}"
RESTIC_KEEP_MONTHLY="${RESTIC_KEEP_MONTHLY:-12}"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

for command in restic flock hostname; do
    command -v "$command" >/dev/null 2>&1 ||
        fail "required command is unavailable: $command"
done

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

for value in \
    "$RESTIC_KEEP_LAST" \
    "$RESTIC_KEEP_DAILY" \
    "$RESTIC_KEEP_WEEKLY" \
    "$RESTIC_KEEP_MONTHLY"
do
    [[ "$value" =~ ^[0-9]+$ ]] ||
        fail "retention values must be non-negative integers"
done

install -d -m 0700 "$RESTIC_CACHE_DIR"

exec 9>"$LOCK_FILE"

if ! flock -n 9; then
    echo "Another ShipIt off-site operation is already running"
    exit 75
fi

echo "Applying off-site retention policy..."

restic forget \
    --host "$RESTIC_HOST" \
    --tag shipit-postgres,production \
    --group-by host,tags \
    --keep-last "$RESTIC_KEEP_LAST" \
    --keep-daily "$RESTIC_KEEP_DAILY" \
    --keep-weekly "$RESTIC_KEEP_WEEKLY" \
    --keep-monthly "$RESTIC_KEEP_MONTHLY" \
    --prune

echo "Checking repository after maintenance..."

restic check

echo "Off-site repository maintenance completed"
