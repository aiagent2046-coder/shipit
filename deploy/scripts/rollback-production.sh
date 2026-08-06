#!/usr/bin/env bash
set -Eeuo pipefail

CONTROL_ROOT="${SHIPIT_CONTROL_ROOT:-/opt/shipit}"
RELEASE_ROOT="${SHIPIT_RELEASE_ROOT:-/srv/shipit}"
ENV_FILE="${SHIPIT_ENV_FILE:-/opt/shipit/.env}"
RELEASE_ENV="${SHIPIT_RELEASE_ENV:-/opt/shipit/.release-env}"
SERVICE="${SHIPIT_SERVICE:-shipit.service}"
FIXPACK_TIMER="${SHIPIT_FIXPACK_TIMER:-shipit-fixpack.timer}"
SYSTEMD_UNIT_SYNC="${SHIPIT_SYSTEMD_UNIT_SYNC:-$CONTROL_ROOT/deploy/scripts/sync-release-systemd-unit.sh}"
LOCK_FILE="${SHIPIT_DEPLOY_LOCK:-/run/lock/shipit-deploy.lock}"

TARGET_SHA=""
PUBLIC_BASE_URL=""

usage() {
  cat <<'EOF'
Usage:
  rollback-production.sh [options]

Options:
  --sha SHA                 Roll back to a specific built release
  --public-base-url URL     Also check public health endpoints
  --help                    Show this help

Without --sha, the release referenced by /srv/shipit/previous is used.
Database migrations are never rolled back by this command.
EOF
}

while (($#)); do
  case "$1" in
    --sha)
      TARGET_SHA="${2:?missing SHA}"
      TARGET_SHA="${TARGET_SHA,,}"
      shift 2
      ;;
    --public-base-url)
      PUBLIC_BASE_URL="${2:?missing URL}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: production rollback must run as root" >&2
  exit 1
fi

mkdir -p "$(dirname "$LOCK_FILE")"

exec 9>"$LOCK_FILE"

if ! flock -n 9; then
  echo "ERROR: another deployment or rollback is running" >&2
  exit 1
fi

MANAGER="$CONTROL_ROOT/deploy/scripts/release_manager.py"
MIGRATION_GATE="$CONTROL_ROOT/deploy/scripts/check_release_migrations.py"
HEALTH_GATE="$CONTROL_ROOT/deploy/scripts/health_gate.py"

if [[ ! -x "$SYSTEMD_UNIT_SYNC" ]]; then
  echo "ERROR: required executable missing: $SYSTEMD_UNIT_SYNC" >&2
  exit 1
fi

FIXPACK_TIMER_WAS_ACTIVE=0
FIXPACK_TIMER_QUIESCED=0

quiesce_fixpack_timer() {
  if systemctl is-active --quiet "$FIXPACK_TIMER"; then
    FIXPACK_TIMER_WAS_ACTIVE=1

    if ! systemctl stop "$FIXPACK_TIMER"; then
      echo "ERROR: could not stop $FIXPACK_TIMER before unit replacement" >&2
      return 1
    fi
  fi

  FIXPACK_TIMER_QUIESCED=1
}

resume_fixpack_timer() {
  if [[ "$FIXPACK_TIMER_QUIESCED" -ne 1 ]]; then
    return 0
  fi

  if [[ "$FIXPACK_TIMER_WAS_ACTIVE" -eq 1 ]]; then
    if ! systemctl start "$FIXPACK_TIMER"; then
      echo "ERROR: could not restart $FIXPACK_TIMER" >&2
      return 1
    fi
  fi

  FIXPACK_TIMER_QUIESCED=0
}

if [[ ! -L "$RELEASE_ROOT/current" ]]; then
  echo "ERROR: no active release symlink exists" >&2
  exit 1
fi

CURRENT_SHA="$(
  basename "$(readlink -f "$RELEASE_ROOT/current")"
)"

if [[ -z "$TARGET_SHA" ]]; then
  if [[ ! -L "$RELEASE_ROOT/previous" ]]; then
    echo "ERROR: no previous release exists" >&2
    exit 1
  fi

  TARGET_SHA="$(
    basename "$(readlink -f "$RELEASE_ROOT/previous")"
  )"
fi

if ! [[ "$TARGET_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: invalid target SHA: $TARGET_SHA" >&2
  exit 1
fi

if [[ "$TARGET_SHA" = "$CURRENT_SHA" ]]; then
  echo "Release is already active: $TARGET_SHA"
  exit 0
fi

TARGET_RELEASE="$RELEASE_ROOT/releases/$TARGET_SHA"
CURRENT_RELEASE="$RELEASE_ROOT/releases/$CURRENT_SHA"

echo "Rollback from: $CURRENT_SHA"
echo "Rollback to:   $TARGET_SHA"

python3 "$MIGRATION_GATE" \
  --release "$TARGET_RELEASE" \
  --env-file "$ENV_FILE"

# shellcheck disable=SC2310
if ! quiesce_fixpack_timer; then
  echo "Production rollback: FAILED before release activation" >&2
  exit 1
fi

if ! "$SYSTEMD_UNIT_SYNC" --release "$TARGET_RELEASE"; then
  echo "Production rollback: target systemd unit installation failed" >&2

  # shellcheck disable=SC2310
  if ! resume_fixpack_timer; then
    echo "WARNING: $FIXPACK_TIMER also failed to restart" >&2
  fi

  exit 1
fi

if ! python3 "$MANAGER" \
  --root "$RELEASE_ROOT" \
  activate \
  --sha "$TARGET_SHA" \
  --release-env "$RELEASE_ENV"
then
  echo \
    "Production rollback: failed to activate rollback target $TARGET_SHA;" \
    "restoring $CURRENT_SHA" \
    >&2

  if ! python3 "$MIGRATION_GATE" \
    --release "$CURRENT_RELEASE" \
    --env-file "$ENV_FILE"
  then
    echo \
      "ERROR: current release failed its migration gate during restoration;" \
      "$FIXPACK_TIMER remains stopped" \
      >&2
    exit 1
  fi

  if ! "$SYSTEMD_UNIT_SYNC" --release "$CURRENT_RELEASE"; then
    echo \
      "ERROR: failed to restore the systemd unit from $CURRENT_SHA;" \
      "$FIXPACK_TIMER remains stopped" \
      >&2
    exit 1
  fi

  if ! python3 "$MANAGER" \
    --root "$RELEASE_ROOT" \
    activate \
    --sha "$CURRENT_SHA" \
    --release-env "$RELEASE_ENV"
  then
    echo \
      "ERROR: failed to reactivate $CURRENT_SHA;" \
      "$FIXPACK_TIMER remains stopped" \
      >&2
    exit 1
  fi

  if ! systemctl restart "$SERVICE"; then
    echo \
      "ERROR: restored $CURRENT_SHA, but $SERVICE did not restart;" \
      "$FIXPACK_TIMER remains stopped" \
      >&2
    exit 1
  fi

  if ! python3 "$HEALTH_GATE" \
    --base-url http://127.0.0.1:8000 \
    --attempts 45 \
    --interval 1 \
    --timeout 3 \
    --consecutive 3
  then
    echo \
      "ERROR: restored $CURRENT_SHA, but it failed its health check;" \
      "$FIXPACK_TIMER remains stopped" \
      >&2
    exit 1
  fi

  if [[ -n "$PUBLIC_BASE_URL" ]]; then
    if ! python3 "$HEALTH_GATE" \
      --base-url "$PUBLIC_BASE_URL" \
      --attempts 20 \
      --interval 1 \
      --timeout 5 \
      --consecutive 2
    then
      echo \
        "ERROR: restored $CURRENT_SHA, but it failed its public health check;" \
        "$FIXPACK_TIMER remains stopped" \
        >&2
      exit 1
    fi
  fi
  # shellcheck disable=SC2310
  if ! resume_fixpack_timer; then
    echo \
      "ERROR: restored $CURRENT_SHA, but $FIXPACK_TIMER did not restart" \
      >&2
    exit 1
  fi

  exit 1
fi

rollback_ok=1

if ! systemctl restart "$SERVICE"; then
  rollback_ok=0
elif ! python3 "$HEALTH_GATE" \
  --base-url http://127.0.0.1:8000 \
  --attempts 45 \
  --interval 1 \
  --timeout 3 \
  --consecutive 3
then
  rollback_ok=0
elif [[ -n "$PUBLIC_BASE_URL" ]] && \
  ! python3 "$HEALTH_GATE" \
    --base-url "$PUBLIC_BASE_URL" \
    --attempts 20 \
    --interval 1 \
    --timeout 5 \
    --consecutive 2
then
  rollback_ok=0
fi

if [[ "$rollback_ok" -ne 1 ]]; then
  echo \
    "Rollback target failed health checks; restoring $CURRENT_SHA" \
    >&2

  python3 "$MIGRATION_GATE" \
    --release "$CURRENT_RELEASE" \
    --env-file "$ENV_FILE"

  if ! "$SYSTEMD_UNIT_SYNC" --release "$CURRENT_RELEASE"; then
    echo \
      "ERROR: failed to restore the systemd unit from $CURRENT_SHA;" \
      "$FIXPACK_TIMER remains stopped" \
      >&2
    exit 1
  fi

  python3 "$MANAGER" \
    --root "$RELEASE_ROOT" \
    activate \
    --sha "$CURRENT_SHA" \
    --release-env "$RELEASE_ENV"

  systemctl restart "$SERVICE"

  python3 "$HEALTH_GATE" \
    --base-url http://127.0.0.1:8000 \
    --attempts 45 \
    --interval 1 \
    --timeout 3 \
    --consecutive 3

  if [[ -n "$PUBLIC_BASE_URL" ]]; then
    if ! python3 "$HEALTH_GATE" \
      --base-url "$PUBLIC_BASE_URL" \
      --attempts 20 \
      --interval 1 \
      --timeout 5 \
      --consecutive 2
    then
      echo \
        "ERROR: restored $CURRENT_SHA, but it failed its public health check;" \
        "$FIXPACK_TIMER remains stopped" \
        >&2
      exit 1
    fi
  fi

  # shellcheck disable=SC2310
  if ! resume_fixpack_timer; then
    echo \
      "ERROR: restored $CURRENT_SHA, but $FIXPACK_TIMER did not restart" \
      >&2
    exit 1
  fi

  exit 1
fi

# shellcheck disable=SC2310
if ! resume_fixpack_timer; then
  echo \
    "Production rollback: $TARGET_SHA is healthy, but" \
    "$FIXPACK_TIMER did not restart" \
    >&2
  exit 1
fi

echo
echo "Production rollback: PASSED"
echo "Active release: $TARGET_SHA"
echo "Database was not modified."
