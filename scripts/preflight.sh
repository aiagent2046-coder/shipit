#!/usr/bin/env bash
# Every CI gate that can run locally, in CI's order, before you push.
#
# Written after two consecutive red builds in one afternoon, both from
# skipping a check that takes seconds here: an unmarked secret-shaped test
# fixture (scan-added-secrets), then a 129-character line (ruff). Neither was
# noise -- both caught something real, and both were found by GitHub two
# minutes after a push instead of by the author two seconds before one. The
# defect was the habit, not the checks.
#
# Usage:
#     scripts/preflight.sh              # against origin/main
#     BASE=origin/release scripts/preflight.sh
#
# Exits non-zero on the FIRST failing gate and names it. Ordered as
# .github/workflows/production-ci.yml orders them, so the gate that fails here
# is the gate that would have failed there.
set -Eeuo pipefail

cd "$(dirname "$0")/.."

BASE="${BASE:-origin/main}"
PY=".venv/bin/python"
RUFF=".venv/bin/ruff"
[ -x "$PY" ] || PY="python3"
[ -x "$RUFF" ] || RUFF="ruff"

# The diff range every diff-scoped gate uses. Resolved once, and resolved
# against the REMOTE base rather than a local branch: CI compares the pull
# request against origin, and a stale local main would scan a different set of
# added lines than CI does -- which is how a local pass turns into a remote
# failure on the same commit.
# Refresh the base first. The first real run of this script compared against a
# local origin/main that was two merges stale, so it scanned a wider diff than
# CI would -- the exact mistake the paragraph above warns about, made by the
# script that warns about it. Best-effort: offline is not a reason to refuse to
# lint, but a stale base must be said out loud rather than assumed away.
if [ -z "${NO_FETCH:-}" ] && [ "${BASE#origin/}" != "$BASE" ]; then
    if ! git fetch --quiet origin "${BASE#origin/}" 2>/dev/null; then
        echo "preflight: could not fetch $BASE, comparing against the local copy" >&2
    fi
fi

if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
    echo "preflight: base '$BASE' not found. Try: git fetch origin main" >&2
    exit 2
fi
HEAD_SHA="$(git rev-parse HEAD)"
BASE_SHA="$(git rev-parse "$BASE")"

# Returning 1 under `set -e` is what stops the run; there is no bookkeeping
# variable, because a second gate's output would only bury the first one's.
gate() {
    local name="$1"; shift
    printf '%-28s' "$name"
    if "$@" >/tmp/preflight.$$ 2>&1; then
        echo "ok"
    else
        echo "FAILED"
        echo "--- $name ---" >&2
        cat /tmp/preflight.$$ >&2
        return 1
    fi
}
trap 'rm -f /tmp/preflight.$$' EXIT

echo "preflight: $BASE ($(git rev-parse --short "$BASE_SHA")) -> HEAD ($(git rev-parse --short "$HEAD_SHA"))"

# ruff and pytest read the working tree; the two diff-scoped gates read
# commits. Left unsaid, that gap lets an uncommitted line pass the whitespace
# and secret gates here and fail them in CI, which is the precise failure this
# script exists to remove.
if ! git diff --quiet HEAD 2>/dev/null; then
    echo "preflight: uncommitted changes — the whitespace and secret gates" \
         "only see committed work. Commit, then re-run." >&2
fi

gate "whitespace"    git diff --check "$BASE_SHA" "$HEAD_SHA"
gate "added secrets" "$PY" .github/scripts/scan-added-secrets.py "$BASE_SHA" "$HEAD_SHA"

# The two shell gates, in CI's order and with CI's exact flags. Their absence
# here contradicted this file's own first line and cost a red build on
# 2026-08-31: a `# shellcheck disable=SC1091` sat above
# `set -a; source keys.env; set +a`, where it bound to `set -a` (a directive
# attaches to the NEXT COMMAND) and suppressed nothing. Seconds to catch here,
# two minutes and a push to catch there -- the same lesson this script's header
# was written for, in the one language it did not cover.
check_shell_syntax() {
    local script
    while IFS= read -r -d '' script; do
        bash -n "$script" || return 1
    done < <(git ls-files -z '*.sh')
}

run_shellcheck() {
    git ls-files -z '*.sh' | xargs -0 shellcheck \
        --severity=info --enable=check-set-e-suppressed
}

gate "shell syntax"  check_shell_syntax

# Not installed everywhere, and a missing linter must not read as a pass. Same
# posture as the ruff-version notice below: say so, do not pretend.
if command -v shellcheck >/dev/null 2>&1; then
    gate "shellcheck"  run_shellcheck
else
    printf '%-28s%s\n' "shellcheck" \
        "NOT INSTALLED — CI runs it; a green here says nothing about it"
    echo "preflight: to match CI: apt-get install shellcheck" >&2
fi

# CI lints with the ruff pinned in requirements-dev.txt; this script lints with
# whatever ruff is on the machine. When those differ, a green line here says
# nothing about the remote one -- a newer ruff carries rules the local one has
# never heard of, and the whole point of this script is that its verdict
# transfers.
#
# Found on 2026-08-26 with the local ruff at 0.15.8 against a pin of 0.16.3:
# two minor versions of rules had never run locally, and nobody knew.
#
# A line, not a gate, for the same reason as the postgres notice below: a
# laptop with a slightly different ruff is a normal place to work, and refusing
# to lint there would teach people to stop running this. Skipping is fine;
# skipping without saying so is not.
PINNED_RUFF="$(sed -n 's/^ruff==\([0-9][0-9.]*\).*/\1/p' requirements-dev.txt | head -1)"
LOCAL_RUFF="$("$RUFF" --version 2>/dev/null | awk '{print $2}')"
if [ -n "$PINNED_RUFF" ] && [ -n "$LOCAL_RUFF" ] && [ "$PINNED_RUFF" != "$LOCAL_RUFF" ]; then
    printf '%-28s%s\n' "ruff version" \
        "LOCAL $LOCAL_RUFF, CI PINS $PINNED_RUFF — a green lint here may be red there"
    echo "preflight: to match CI: $PY -m pip install 'ruff==$PINNED_RUFF'" >&2
fi

gate "ruff"          "$RUFF" check .
gate "pytest"        "$PY" -m pytest -q

# The Postgres smoke suite is collected by the gate above and SKIPS itself
# without a database, so a green pytest here can mean "everything passed" or
# "everything runnable passed" -- and those look identical.
#
# On 2026-08-25 a keyword argument gained a required parameter, every call site
# in tests/ was updated except the one in test_db_postgres_smoke.py, preflight
# said all gates passed, and CI failed on a TypeError. The suite was not run;
# it was skipped, silently, in the middle of a count of passes.
#
# Not a gate, because a laptop without Postgres is a normal place to work and
# refusing to finish there would teach people to stop running this. A line
# instead, in the same spirit as the web block below: skipping is fine, and
# skipping without saying so is not.
if [ -z "${DATABASE_URL:-}" ]; then
    echo "postgres smoke              SKIPPED (no DATABASE_URL; CI runs it)"
fi

# The web build is the slowest gate and the only one that needs node_modules,
# so it runs only when the diff can affect it. Skipping it silently when web/
# is untouched is correct; skipping it silently when web/ IS touched is how a
# types.ts change reaches CI unbuilt.
if git diff --name-only "$BASE_SHA" "$HEAD_SHA" | grep -q '^web/'; then
    # A DEPENDENCY CHANGE MAKES node_modules A LIE, and the tests do not
    # notice. On 2026-08-26 a Dependabot branch bumped @vitejs/plugin-react to
    # a version whose peer range demands vite 8 while the lockfile still
    # pinned vite 7. `npm ci` refused the tree -- in CI and locally -- but the
    # node_modules left over from main's install was still on disk, so vitest
    # ran happily against the OLD dependencies and reported 60 passing tests
    # for a branch that could not install at all.
    #
    # So when the manifest or the lockfile moves, install exactly what they
    # say before believing anything. This is `npm ci` for the same reason CI
    # uses it: it deletes node_modules and builds from the lockfile, which is
    # the only way the run is about the branch in front of you.
    #
    # A GATE, not a notice, unlike the ruff and postgres cases above. Those
    # are "this machine cannot check that"; this one is "the check ran and was
    # about something else", which is worse than not running it.
    if git diff --name-only "$BASE_SHA" "$HEAD_SHA" \
        | grep -qE '^web/(package\.json|package-lock\.json)$'; then
        gate "npm ci"     bash -c 'cd web && npm ci'
    fi
    if [ -d web/node_modules ]; then
        # Before the build, and the cheap one of the pair: about a second
        # against about twenty. It also fails on a different class -- the build
        # rejects a component that cannot compile, this rejects one that
        # compiles and behaves wrongly.
        gate "vitest"     bash -c 'cd web && npx vitest run'
        gate "next build" bash -c 'cd web && npx next build'
    else
        echo "vitest                      SKIPPED (web/node_modules missing; run: cd web && npm ci)"
        echo "next build                  SKIPPED (web/node_modules missing; run: cd web && npm ci)"
        echo "preflight: web/ changed but its build did not run -- CI will build it" >&2
    fi
fi

echo "preflight: all gates passed"
