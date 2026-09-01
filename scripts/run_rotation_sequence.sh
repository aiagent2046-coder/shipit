#!/usr/bin/env bash
# The four rotation runs, as one sequence that cannot drift from its own state.
#
# WHY THIS IS A SCRIPT AND NOT FOUR PASTED COMMANDS. The first attempt was four
# `run` calls with `ln -sfn` between them, and every run returned 429. The
# symlinks advanced anyway: the stand ended up serving dist_clean while nothing
# had been measured at all. Had the 429 arrived on the third run instead of the
# first, the fourth would have compared a verdict against a variant that was
# never live when it was checked, and the output would have looked ordinary.
#
# So state is SET per step rather than advanced between them, the served bundle
# is confirmed to be the variant just selected before any request is made, and
# any failure stops the sequence instead of carrying on into a comparison whose
# baseline is now a guess.
#
# THE ORDER IS THE MEASUREMENT. Each verdict is only meaningful as the successor
# of the one before:
#
#   1  key A, no prior check          -> no_baseline
#   2  key A again, unchanged bundle  -> unchanged
#   3  key B, same class, new key     -> replaced_still_shipped
#   4  anon only, credential removed  -> gone_from_bundle
#
# A skipped or failed step does not just lose one result, it invalidates every
# result after it.
#
# Budget: four of the endpoint's five daily requests. Run
# scripts/preflight_bundle_check.py first — it exercises the same fetch for
# free, and a sequence started against an unreadable URL spends the day.
#
#   DB=... AUDIT_ID=... scripts/run_rotation_sequence.sh
set -euo pipefail

STAND_ROOT=${STAND_ROOT:-/srv/rotation-stand}
STAND_URL=${STAND_URL:-https://rotation-stand.45-10-40-169.sslip.io/}
API=${API:-https://api.drydock.co}
OUT_DIR=${OUT_DIR:-/root}
AUDIT_ID=${AUDIT_ID:?set AUDIT_ID}
DB=${DB:?set DB to the production DATABASE_URL}

# Read once. The token is a per-row capability for one audit; it stays in this
# variable and is never echoed, logged or written to a file.
TOKEN=$(psql "$DB" -At -c \
    "select access_token from audits where id = '$AUDIT_ID'")
if [ -z "$TOKEN" ]; then
    echo "no audit $AUDIT_ID, or its access_token is null" >&2
    exit 1
fi

serve() {
    # Point the stand at one variant and PROVE the switch took effect before
    # anything is spent. The entry chunk's name carries a hash of its contents,
    # so a served name that does not match the variant's own file means the
    # deployment is not what the next request will be told it is.
    local variant="$1" want served
    ln -sfn "$STAND_ROOT/$variant" "$STAND_ROOT/current"
    want=$(basename "$(echo "$STAND_ROOT/$variant"/assets/entry-*.js)")
    served=$(curl -fsS "$STAND_URL" | grep -o 'entry-[a-z0-9]*\.js' | head -1)
    if [ "$served" != "$want" ]; then
        echo "stand serves $served but $variant is $want -- refusing to spend" >&2
        exit 1
    fi
    echo "  serving $variant ($want)"
}

check() {
    # One request, and the sequence stops on anything but a 200 with the
    # expected verdict. A 429 here is not a hiccup to retry past: the next step
    # would change the bundle underneath a baseline that was never recorded.
    local n="$1" want="$2" out code verdict
    out="$OUT_DIR/rot-$n.json"
    code=$(curl -sS -X POST "$API/v1/audits/$AUDIT_ID/bundle-check" \
        -F "deployment_url=$STAND_URL" \
        -F "consent=i-own-this-project" \
        -F "token=$TOKEN" \
        -o "$out" -w '%{http_code}')
    if [ "$code" != "200" ]; then
        echo "  HTTP $code -- stopping, the sequence cannot continue" >&2
        cat "$out" >&2
        exit 1
    fi
    verdict=$(python3 -c \
        'import json,sys; d=json.load(open(sys.argv[1]));
print((d.get("rotation") or {}).get("verdict"), len(d.get("findings") or []))' \
        "$out")
    echo "  run $n: $verdict (expected $want) -> $out"
    case "$verdict" in
        "$want"*) ;;
        *) echo "  UNEXPECTED verdict -- stopping before the next step "\
                "changes the bundle" >&2; exit 1 ;;
    esac
}

step() {
    echo "step $1 ($3)"
    serve "$2"
    check "$1" "$3"
}

step 1 dist_key_a no_baseline
step 2 dist_key_a unchanged
step 3 dist_key_b replaced_still_shipped
step 4 dist_clean gone_from_bundle

unset TOKEN
echo
echo "four verdicts recorded in $OUT_DIR/rot-{1,2,3,4}.json"
echo "the stand is left serving dist_clean, which carries no credential."
