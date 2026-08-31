#!/usr/bin/env bash
# Build the two variants of the stand from ONE source, differing only in the key
# baked into the bundle:
#
#   dist_vulnerable/  VITE_SUPABASE_KEY = the service_role JWT  (the leak)
#   dist_patched/     VITE_SUPABASE_KEY = the anon JWT          (the fix)
#
# The fix for this class is not a code change — the createClient line is
# identical — it is which key the build publishes. That is why the two dirs come
# from the same src/ with a different env, and it is what the e2e then proves
# end to end against a live PostgREST.
set -euo pipefail
cd "$(dirname "$0")"

# shellcheck disable=SC1091
set -a; source keys.env; set +a

URL="http://127.0.0.1:54399"   # the local stand's PostgREST; overridden by the e2e

echo "building VULNERABLE variant (service_role key in the client)…"
rm -rf dist_vulnerable
VITE_SUPABASE_URL="$URL" VITE_SUPABASE_KEY="$SERVICE_ROLE_JWT" \
  npx vite build --outDir dist_vulnerable --emptyOutDir >/dev/null

echo "building PATCHED variant (anon key only)…"
rm -rf dist_patched
VITE_SUPABASE_URL="$URL" VITE_SUPABASE_KEY="$ANON_JWT" \
  npx vite build --outDir dist_patched --emptyOutDir >/dev/null

echo "done: dist_vulnerable/ and dist_patched/"
