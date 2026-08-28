#!/usr/bin/env bash
set -Eeuo pipefail

CONTROL_ROOT="${SHIPIT_CONTROL_ROOT:-/opt/shipit}"
RELEASE_ROOT="${SHIPIT_RELEASE_ROOT:-/srv/shipit}"
ENV_FILE="${SHIPIT_ENV_FILE:-/opt/shipit/.env}"
RELEASE_ENV="${SHIPIT_RELEASE_ENV:-/opt/shipit/.release-env}"
SERVICE="${SHIPIT_SERVICE:-shipit.service}"
WORKER_SERVICE="${SHIPIT_WORKER_SERVICE:-shipit-audit-worker.service}"
FIXPACK_TIMER="${SHIPIT_FIXPACK_TIMER:-shipit-fixpack.timer}"
SYSTEMD_UNIT_SYNC="${SHIPIT_SYSTEMD_UNIT_SYNC:-$CONTROL_ROOT/deploy/scripts/sync-release-systemd-unit.sh}"
LOCK_FILE="${SHIPIT_DEPLOY_LOCK:-/run/lock/shipit-deploy.lock}"
KEEP_RELEASES="${SHIPIT_KEEP_RELEASES:-5}"

REVISION="origin/main"
PUBLIC_BASE_URL=""
SKIP_FETCH=0
ALLOW_SAME_REVISION=0

usage() {
  cat <<'EOF'
Usage:
  deploy-production.sh [options]

Options:
  --revision REVISION       Git revision to deploy (default: origin/main)
  --public-base-url URL     Also check public health endpoints
  --skip-fetch              Do not fetch origin/main
  --allow-same-revision     Redeploy the commit already running
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
    --allow-same-revision)
      ALLOW_SAME_REVISION=1
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

# Captured once and PRINTED, not just tested. This refused a deploy three
# times in a row saying only "uncommitted changes", and finding out that the
# offender was a single stray `dub_after.json` -- an audit result curled into
# the control checkout by an operator who never left the directory -- took
# three round trips and a false conclusion in between.
#
# The output is what makes the fix obvious: `??` is a stray file to move
# aside, ` M` is somebody's edit to read before touching. A gate that refuses
# without naming what it saw sends the reader to guess, and the first guess
# on a `??` line is `git reset --hard`, which is precisely the command this
# gate exists to stand in front of.
#
# Same lesson as tag-release.sh's header, one script over: under `set -e`, a
# step that cannot name its own failure reads as arbitrary.
dirty="$(git status --porcelain)"
if [[ -n "$dirty" ]]; then
  echo "ERROR: control repository has uncommitted changes:" >&2
  printf '%s\n' "$dirty" >&2
  echo "  '??' is an untracked stray -- move it out of $CONTROL_ROOT." >&2
  echo "  ' M' is an edit to somebody's file -- read it before removing it." >&2
  exit 1
fi

if [[ "$SKIP_FETCH" -eq 0 ]]; then
  # --tags is not redundant. Tag auto-following only applies to the refs being
  # fetched, and this fetch is branch-scoped, so a release tag would never
  # arrive and `git rev-parse v2026.08.07-1^{commit}` below would fail with
  # "Needed a single revision" -- deploying by tag would be impossible on a
  # host that had not seen the tag by some other route.
  git fetch --prune --tags origin main
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

# Bring the control checkout itself to the revision being deployed, BEFORE the
# tooling below is located and run.
#
# The deploy tooling is versioned with the application but executed from this
# long-lived working tree, not from the release being built. `git fetch`
# updates refs and leaves the working tree alone, so without this the build is
# performed by whatever builder was checked out last -- an OLD builder
# producing a NEW release. That is not hypothetical: the first CalVer release
# deployed cleanly and still reported `version: null`, because the previous
# builder wrote the metadata and knew nothing about the git_describe field the
# new code reads.
#
# Safe to replace this very script mid-run: `git checkout` writes a new file
# and renames it, so the inode bash is reading from is unchanged and the
# running process finishes from the original text. (Verified: an in-place
# truncating writer such as `cat >` WOULD corrupt a running script; git does
# not do that.) The updated script takes effect on the next invocation.
#
# The working tree is known clean -- the preflight above refuses to run with
# uncommitted changes -- so this cannot silently discard local edits.
if [[ "$(git rev-parse HEAD)" != "$TARGET_SHA" ]]; then
  echo "Syncing control checkout: $(git rev-parse --short HEAD) -> ${TARGET_SHA:0:7}"
  git checkout --quiet --detach "$TARGET_SHA"
fi

MANAGER="$CONTROL_ROOT/deploy/scripts/release_manager.py"
MIGRATION_GATE="$CONTROL_ROOT/deploy/scripts/check_release_migrations.py"
HEALTH_GATE="$CONTROL_ROOT/deploy/scripts/health_gate.py"

for file in \
  "$MANAGER" \
  "$MIGRATION_GATE" \
  "$HEALTH_GATE" \
  "$SYSTEMD_UNIT_SYNC" \
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

# Deploying the commit that is already running is almost always an accident,
# and it is the one accident this script cannot otherwise report: every stage
# passes, the health checks pass, and the run ends in "Production deployment:
# PASSED" having changed nothing.
#
# It happened on 2026-08-11. Nine commits sat on an unmerged branch,
# tag-release.sh tagged origin/main as it is supposed to, and v2026.08.11-2
# was cut against the same commit as v2026.08.11-1. The deploy was green, the
# new work was not in production, and the only way to know was to compare the
# two lines printed directly above against a commit held in someone's head.
#
# The two lines were already there. They were not enough, so this exits.
#
# Not a hard refusal: re-deploying the running commit is legitimate after a
# host is rebuilt, after a manual change on the box, or to recover a release
# whose build is suspect. --allow-same-revision says that out loud, which is
# the whole difference between the deliberate case and the accident.
if [[ -n "$CURRENT_SHA" && "$CURRENT_SHA" == "$TARGET_SHA" ]]; then
  if ((ALLOW_SAME_REVISION)); then
    echo "NOTE: redeploying the running commit, as requested."
  else
    {
      echo
      echo "ERROR: $REVISION already resolves to the running release."
      echo "       Nothing would change, and the run would still report PASSED."
      echo
      echo "  If work is missing from this deployment, it is not merged yet:"
      echo "  release tags are cut against origin/main, so a tag made while a"
      echo "  branch is unmerged points at the commit already deployed. Merge,"
      echo "  cut a new tag, and deploy that."
      echo
      echo "  To redeploy this exact commit on purpose -- a rebuilt host, a"
      echo "  manual change on the box, a build you no longer trust -- pass"
      echo "  --allow-same-revision."
      echo
    } >&2
    exit 1
  fi
fi

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


# EVERY step below is checked explicitly, and that is not a style choice.
#
# This function is called from a conditional context (see the call site), and
# bash disables errexit for the whole body of a function invoked that way --
# inside `f || true`, inside `if f; then`, inside `f && g`, all of them. So
# `set -Eeuo pipefail` at the top of this file does NOT protect anything in
# here. Before these checks existed, all four steps ran regardless of whether
# the previous one failed, and the success line at the bottom printed
# unconditionally: a rollback that never switched the symlink and never passed
# a health check still reported "Automatic rollback completed".
#
# Switching the call site to `if rollback_after_failure ...` would NOT have
# fixed it. The suppression comes from the conditional context, not from the
# `|| true`.
#
# Returns 0 only when the service is actually back on the previous release and
# answering. Any other outcome returns non-zero after saying which step failed.
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

  if [[ ! -d "$original_release" ]]; then
    echo \
      "ROLLBACK FAILED at step 'locate release': $original_release is gone" \
      >&2
    return 1
  fi

  # The gate refuses when the database schema is ahead of the release being
  # activated -- which is exactly the case whenever the failed deployment
  # carried a migration. That refusal is correct (old code against a newer
  # schema is its own outage) but it means the automatic path is unavailable
  # precisely when a deployment was riskiest, so say so in those words rather
  # than let it read as a generic failure.
  if ! python3 "$MIGRATION_GATE" \
    --release "$original_release" \
    --env-file "$ENV_FILE"
  then
    echo >&2
    echo \
      "ROLLBACK FAILED at step 'migration gate': the database schema is" \
      "ahead of $original_sha, so restoring that code would run it against a" \
      "schema it does not know. The service is still on the FAILED release." \
      "Roll the schema back by hand, or fix forward." >&2
    return 1
  fi

  if ! "$SYSTEMD_UNIT_SYNC" --release "$original_release"; then
    echo \
      "ROLLBACK FAILED at step 'systemd unit': could not install the unit from" \
      "$original_sha. The active release was not switched and the timer" \
      "remains stopped." >&2
    return 1
  fi

  if ! python3 "$MANAGER" \
    --root "$RELEASE_ROOT" \
    activate \
    --sha "$original_sha" \
    --release-env "$RELEASE_ENV"
  then
    echo \
      "ROLLBACK FAILED at step 'activate': the unit from $original_sha was" \
      "installed, but current could not be pointed at that release. The" \
      "symlink may be in either state; the timer remains stopped." >&2
    return 1
  fi

  if ! systemctl restart "$SERVICE"; then
    echo \
      "ROLLBACK FAILED at step 'restart': $SERVICE did not restart on" \
      "$original_sha. The symlink IS rolled back, so a manual" \
      "'systemctl restart $SERVICE' is the next thing to try." >&2
    return 1
  fi

  if ! python3 "$HEALTH_GATE" \
    --base-url http://127.0.0.1:8000 \
    --attempts 45 \
    --interval 1 \
    --timeout 3 \
    --consecutive 3
  then
    echo \
      "ROLLBACK FAILED at step 'local health': $original_sha is activated and" \
      "the service restarted, but it is not answering on 127.0.0.1:8000." \
      "The previous release is not healthy either -- this is an outage." >&2
    return 1
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
        "ROLLBACK FAILED at step 'public health': $original_sha is healthy" \
        "locally but not reachable at $PUBLIC_BASE_URL. Look at the edge" \
        "(Caddy, DNS, TLS) rather than at the release." >&2
      return 1
    fi
  fi

  # shellcheck disable=SC2310
  if ! resume_fixpack_timer; then
    echo \
      "ROLLBACK FAILED at step 'timer': $original_sha is healthy, but" \
      "$FIXPACK_TIMER could not be restarted." >&2
    return 1
  fi

  echo "Automatic rollback completed: $original_sha"
}

# shellcheck disable=SC2310
if ! quiesce_fixpack_timer; then
  echo "Production deployment: FAILED before release activation" >&2
  exit 1
fi

if ! "$SYSTEMD_UNIT_SYNC" --release "$RELEASE_ROOT/releases/$TARGET_SHA"; then
  echo "Production deployment: systemd unit installation failed" >&2

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
    "Production deployment: failed to activate $TARGET_SHA" \
    >&2

  # shellcheck disable=SC2310
  if ! rollback_after_failure "$CURRENT_SHA"; then
    echo >&2
    echo \
      "Production deployment: FAILED, AND ROLLBACK FAILED" \
      >&2
    exit 1
  fi

  echo >&2
  echo \
    "Production deployment: FAILED (rolled back to $CURRENT_SHA)" \
    >&2
  exit 1
fi

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
  # `|| true` here is what silenced the whole function (see the comment on it).
  # The status is captured instead, so a failed rollback is loud and a
  # successful one still exits non-zero -- the DEPLOYMENT failed either way.
  rollback_status=0
  # shellcheck disable=SC2310  # errexit IS suppressed in the function body
  # here, and that is accounted for: rollback_after_failure checks every step
  # itself and returns non-zero on the first failure, which is the whole point
  # of this change. The warning is left visible rather than the check disabled
  # tree-wide, so the next `f || true` somewhere else still fails CI.
  rollback_after_failure "$CURRENT_SHA" || rollback_status=$?

  if [[ "$rollback_status" -ne 0 ]]; then
    echo >&2
    echo "Production deployment: FAILED, AND ROLLBACK FAILED" >&2
    echo "This host needs manual intervention now. See the step above." >&2
    exit 1
  fi

  echo >&2
  echo "Production deployment: FAILED (rolled back to $CURRENT_SHA)" >&2
  exit 1
fi

# shellcheck disable=SC2310
if ! resume_fixpack_timer; then
  echo >&2
  echo "Production deployment: the API is live on $TARGET_SHA, but" >&2
  echo "$FIXPACK_TIMER did not restart." >&2
  echo >&2
  echo "Deliberately NOT rolled back: the release passed its health gates." >&2
  echo "Next: systemctl status $FIXPACK_TIMER" >&2
  exit 1
fi

# The audit worker runs the scan itself, and it is a long-lived Type=simple
# process: swapping the `current` symlink does not touch the Python already
# running out of the previous release. Nothing here restarted it, so every
# deployment before this one left the scanner on old code until something
# unrelated -- a crash, a reboot, a human -- happened to bounce it. An engine
# fix could ship, pass both health gates, print PASSED, and never reach a
# single audit. That is not hypothetical: it is how 2026-08-03's false-positive
# fix behaved until the worker was restarted by hand.
#
# After the health gates, deliberately. If the new release is bad we roll back
# without ever having pointed the worker at it, which is why the rollback path
# above says nothing about the worker -- there is nothing to undo.
#
# Restarting mid-job is safe by construction: the queue claims each job into a
# lease and re-queues leases older than 15 minutes, up to 3 attempts.
if ! systemctl cat "$WORKER_SERVICE" >/dev/null 2>&1; then
  echo
  echo "NOTE: $WORKER_SERVICE is not installed here, so it was not restarted."
  echo "      That unit is what scans audits. If this host is meant to run"
  echo "      them, install it (see README, 'Installing the timers')."
elif ! systemctl restart "$WORKER_SERVICE"; then
  echo >&2
  echo "Production deployment: the API is live on $TARGET_SHA, but" >&2
  echo "$WORKER_SERVICE did not restart." >&2
  echo >&2
  echo "Deliberately NOT rolled back: the release passed both health gates," >&2
  echo "so the API is serving it correctly and undoing that would trade a" >&2
  echo "working API for a broken one. What is broken is the scanner, which" >&2
  echo "is either down or still running the previous release." >&2
  echo "Next: systemctl status $WORKER_SERVICE" >&2
  exit 1
fi

python3 "$MANAGER" \
  --root "$RELEASE_ROOT" \
  prune \
  --keep "$KEEP_RELEASES"

echo
echo "Production deployment: PASSED"
echo "Active release: $TARGET_SHA"
