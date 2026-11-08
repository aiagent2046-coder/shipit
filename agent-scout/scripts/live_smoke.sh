#!/bin/bash
# Live smoke for agent-scout: exercises the REAL network paths (unit tests
# never leave localhost). Sandbox HOME - the operator registry is untouched.
#
#   bash scripts/live_smoke.sh
#
# ~3 minutes: manifest probing is politely paced (1 request/second per host).
# Every step checks the output marker and the exit code. One product-contract
# nuance is encoded: `scan --url` exits 1 when the target has no public
# manifests (nothing to assess - the honest profile-only outcome), so that
# step accepts rc=1 alongside its report marker.
# Exit code = number of failed steps (0 = SMOKE OK).
set -u

REAL_HOME="${HOME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOUT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCOUT_DIR/.." && pwd)"
SMOKE_HOME="$(mktemp -d /tmp/scout-smoke.XXXXXX)"
export HOME="$SMOKE_HOME"
export SCOUT_SHIPIT_ROOT="${SCOUT_SHIPIT_ROOT:-$REPO_ROOT}"
if [ -x "$SCOUT_DIR/.venv/bin/scout" ]; then
  SCOUT="$SCOUT_DIR/.venv/bin/scout"
elif [ -x "$REPO_ROOT/.venv/bin/python" ]; then
  SCOUT="$REPO_ROOT/.venv/bin/python -m scout.cli"
else
  SCOUT="python3 -m scout.cli"
fi
cd "$SCOUT_DIR" || exit 1

SMOKE_URL="${SMOKE_URL:-https://www.mozilla.org}"
SMOKE_REPO="${SMOKE_REPO:-hoppscotch/hoppscotch}"
SMOKE_QUERY="${SMOKE_QUERY:-langflow}"
OUT="$SMOKE_HOME/out"

fails=0
skips=0
step_no=0
step() {
  local name="$1" expect="$2" rc1_ok="$3"
  shift 3
  step_no=$((step_no + 1))
  local log="$SMOKE_HOME/step-$step_no.log"
  "$@" >"$log" 2>&1
  local rc=$?
  if grep -q "rate limited" "$log"; then
    echo "SKIP  $name (remote API rate limit - retry later)"
    skips=$((skips + 1))
    return
  fi
  if { [ "$rc" -eq 0 ] || { [ "$rc1_ok" = "rc1-ok" ] && [ "$rc" -eq 1 ]; }; } \
     && { [ -z "$expect" ] || grep -Eq "$expect" "$log"; }; then
    echo "PASS  $name"
  else
    echo "FAIL  $name (rc=$rc, log: $log)"
    fails=$((fails + 1))
  fi
}

step "scan --url: profile + security.txt + source maps" \
  "report:" rc1-ok $SCOUT scan --url "$SMOKE_URL" --out "$OUT"
step "scan --repo: manifest probes + engine" \
  "findings:" strict $SCOUT scan --repo "$SMOKE_REPO" --out "$OUT"
step "hunt --source gitlab: candidate search + manifests" \
  "hunt report:" strict $SCOUT hunt --query "$SMOKE_QUERY" --limit 1 --source gitlab --out "$OUT"
step "registry list" \
  "drafted" strict $SCOUT registry list
step "registry refresh --re-record: refetch + verify + contact backfill" \
  "refresh:" strict $SCOUT registry refresh --re-record
step "outreach send --dry-run: quota machinery" \
  "nothing sent|nothing to deliver" strict $SCOUT outreach send --dry-run

echo "----"
echo "sandbox: $SMOKE_HOME (operator registry untouched: $REAL_HOME/.agent-scout)"
if [ "$fails" -eq 0 ]; then
  echo "SMOKE OK ($skips skipped)"
else
  echo "SMOKE FAILED: $fails step(s), $skips skipped"
fi
exit "$fails"
