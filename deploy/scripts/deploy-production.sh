#!/usr/bin/env bash
set -Eeuo pipefail

CONTROL_ROOT="${SHIPIT_CONTROL_ROOT:-/opt/shipit}"
RELEASE_ROOT="${SHIPIT_RELEASE_ROOT:-/srv/shipit}"
ENV_FILE="${SHIPIT_ENV_FILE:-/opt/shipit/.env}"
RELEASE_ENV="${SHIPIT_RELEASE_ENV:-/opt/shipit/.release-env}"
SERVICE="${SHIPIT_SERVICE:-shipit.service}"
LOCK_FILE="${SHIPIT_DEPLOY_LOCK:-/run/lock/shipit-deploy.lock}"
KEEP_RELEASES="${SHIPIT_KEEP_RELEASES:-5}"

REVISION="origin/main"
PUBLIC_BASE_URL=""
SKIP_FETCH=0

usage() {
  cat <<'EOF'
Usage:
  deploy-production.sh [options]

Options:
  --revision REVISION       Git revision to deploy (default: origin/main)
  --public-base-url URL     Also check public health endpoints
  --skip-fetch              Do not fetch origin/main
  --help                    Show this help
EOF
}

while (($#)); do
  case "$1" in
    --revision)
      REVISION="${2:?missing revision}"
      shift 2
      ;;
    --public-base-url)
      PUBLIC_BASE_URL="${2:?missing URL}"
      shift 2
      ;;
    --skip-fetch)
      SKIP_FETCH=1
      shift
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
  echo "ERROR: production deployment must run as root" >&2
  exit 1
fi

command -v flock >/dev/null
command -v git >/dev/null
command -v systemctl >/dev/null
command -v python3 >/dev/null

mkdir -p "$(dirname "$LOCK_FILE")"

exec 9>"$LOCK_FILE"

if ! flock -n 9; then
  echo "ERROR: another deployment or rollback is running" >&2
  exit 1
fi

cd "$CONTROL_ROOT"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: control repository has uncommitted changes" >&2
  exit 1
fi

if [[ "$SKIP_FETCH" -eq 0 ]]; then
  git fetch --prune origin main
fi

TARGET_SHA="$(
  git rev-parse \
    --verify \
    "${REVISION}^{commit}"
)"

TARGET_SHA="${TARGET_SHA,,}"

if ! [[ "$TARGET_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: invalid target SHA: $TARGET_SHA" >&2
  exit 1
fi

if git show-ref --verify --quiet refs/remotes/origin/main; then
  if ! git merge-base \
    --is-ancestor \
    "$TARGET_SHA" \
    origin/main
  then
    echo \
      "ERROR: target commit is not contained in origin/main" \
      >&2
    exit 1
  fi
fi

MANAGER="$CONTROL_ROOT/deploy/scripts/release_manager.py"
MIGRATION_GATE="$CONTROL_ROOT/deploy/scripts/check_release_migrations.py"
HEALTH_GATE="$CONTROL_ROOT/deploy/scripts/health_gate.py"

for file in \
  "$MANAGER" \
  "$MIGRATION_GATE" \
  "$HEALTH_GATE" \
  "$ENV_FILE"
do
  if [[ ! -f "$file" ]]; then
    echo "ERROR: required file missing: $file" >&2
    exit 1
  fi
done

CURRENT_SHA=""

if [[ -L "$RELEASE_ROOT/current" ]]; then
  CURRENT_TARGET="$(readlink -f "$RELEASE_ROOT/current")"
  CURRENT_SHA="$(basename "$CURRENT_TARGET")"
fi

echo "Target release:  $TARGET_SHA"
echo "Current release: ${CURRENT_SHA:-none}"

python3 "$MANAGER" \
  --root "$RELEASE_ROOT" \
  build \
  --repo "$CONTROL_ROOT" \
  --revision "$TARGET_SHA" \
  --python "$(command -v python3)"

TARGET_RELEASE="$RELEASE_ROOT/releases/$TARGET_SHA"

"$TARGET_RELEASE/.venv/bin/python" \
  "$TARGET_RELEASE/deploy/scripts/validate-production-env.py" \
  --env-file "$ENV_FILE"

python3 "$MIGRATION_GATE" \
  --release "$TARGET_RELEASE" \
  --env-file "$ENV_FILE"

rollback_after_failure() {
  local original_sha="$1"

  echo
  echo "Deployment failed. Starting automatic code rollback." >&2

  if [[ -z "$original_sha" ]]; then
    echo \
      "ERROR: no previous release exists; automatic rollback unavailable" \
      >&2
    return 1
  fi

  local original_release="$RELEASE_ROOT/releases/$original_sha"

  python3 "$MIGRATION_GATE" \
    --release "$original_release" \
    --env-file "$ENV_FILE"

  python3 "$MANAGER" \
    --root "$RELEASE_ROOT" \
    activate \
    --sha "$original_sha" \
    --release-env "$RELEASE_ENV"

  systemctl restart "$SERVICE"

  python3 "$HEALTH_GATE" \
    --base-url http://127.0.0.1:8000 \
    --attempts 45 \
    --interval 1 \
    --timeout 3 \
    --consecutive 3

  if [[ -n "$PUBLIC_BASE_URL" ]]; then
    python3 "$HEALTH_GATE" \
      --base-url "$PUBLIC_BASE_URL" \
      --attempts 20 \
      --interval 1 \
      --timeout 5 \
      --consecutive 2
  fi

  echo "Automatic rollback completed: $original_sha"
}

python3 "$MANAGER" \
  --root "$RELEASE_ROOT" \
  activate \
  --sha "$TARGET_SHA" \
  --release-env "$RELEASE_ENV"

deployment_ok=1

if ! systemctl restart "$SERVICE"; then
  deployment_ok=0
elif ! python3 "$HEALTH_GATE" \
  --base-url http://127.0.0.1:8000 \
  --attempts 45 \
  --interval 1 \
  --timeout 3 \
  --consecutive 3
then
  deployment_ok=0
elif [[ -n "$PUBLIC_BASE_URL" ]] && \
  ! python3 "$HEALTH_GATE" \
    --base-url "$PUBLIC_BASE_URL" \
    --attempts 20 \
    --interval 1 \
    --timeout 5 \
    --consecutive 2
then
  deployment_ok=0
fi

if [[ "$deployment_ok" -ne 1 ]]; then
  rollback_after_failure "$CURRENT_SHA" || true
  exit 1
fi

python3 "$MANAGER" \
  --root "$RELEASE_ROOT" \
  prune \
  --keep "$KEEP_RELEASES"

echo
echo "Production deployment: PASSED"
echo "Active release: $TARGET_SHA"
