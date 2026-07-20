#!/usr/bin/env bash
# Apply every migration in migrations/ to $DATABASE_URL, in filename order.
#
# There is no migration framework in this project (no alembic, no migrate) --
# the user applies migrations by hand via Supabase's tool one at a time. This
# script is the "apply all in order" mechanism the real-Postgres CI smoke test
# needs (see .github/workflows/db-postgres-smoke.yml and
# POSTGRES_CI_SMOKE_TEST_PLAN.md), and it doubles as a way to stand up the
# schema against a throwaway local Postgres for the same smoke test.
#
# The files are zero-padded (0001..0015), so lexical order == numeric order.
# They are idempotent (create ... if not exists / add column if not exists), so
# re-running is safe. ON_ERROR_STOP=1 makes a broken migration fail loudly
# instead of continuing past a half-applied schema.
#
# Usage:
#   export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
#   bash scripts/apply_migrations.sh
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is not set -- export it first, see this script header}"

# Resolve migrations/ relative to the repo root (this script's parent dir),
# so it works regardless of the caller's working directory.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

shopt -s nullglob
migrations=("$REPO_ROOT"/migrations/[0-9]*.sql)
if [ ${#migrations[@]} -eq 0 ]; then
  echo "no migrations found under $REPO_ROOT/migrations" >&2
  exit 1
fi

for f in "${migrations[@]}"; do
  echo "=== applying $(basename "$f") ==="
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 --no-psqlrc --quiet -f "$f"
done

echo "=== all ${#migrations[@]} migrations applied ==="
