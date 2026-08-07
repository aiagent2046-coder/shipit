#!/usr/bin/env bash
set -Eeuo pipefail

# Create the CalVer release tag for a commit you are about to deploy.
#
# Scheme: v<YYYY.MM.DD>-<n>, dated in UTC, with n starting at 1 and counting
# releases tagged on that same UTC day (v2026.08.07-1, v2026.08.07-2, ...).
#
# Why CalVer and not semver: this is a continuously deployed service, not a
# library anyone imports. Its public contract is already versioned in the URL
# path (/v1/...), so a semver major/minor/patch on the deployment would have to
# be assigned by taste, and "how old is production" — the question that
# actually gets asked during an incident — would still need a lookup. A date
# answers it directly. The per-day counter exists because several releases a
# day is normal here.
#
# ORDER MATTERS: tag BEFORE you deploy.
#
#   release_manager.py records `git describe` into the release metadata at
#   BUILD time, and /version reports it from there. A tag pushed after the
#   build cannot reach that already-written metadata, so the running release
#   keeps reporting a bare short SHA until it is rebuilt. Tagging afterwards
#   still marks history correctly, but it buys nothing at runtime.
#
# Usage:
#   deploy/scripts/tag-release.sh                     # tag origin/main, local only
#   deploy/scripts/tag-release.sh --push              # ... and push the tag
#   deploy/scripts/tag-release.sh --revision <rev>    # tag a specific commit
#
# Then deploy the tag it printed:
#   deploy/scripts/deploy-production.sh --revision v2026.08.07-1

REMOTE="${SHIPIT_TAG_REMOTE:-origin}"
REVISION="origin/main"
PUSH=0
SKIP_FETCH=0

usage() {
  cat <<'EOF'
Usage:
  tag-release.sh [options]

Options:
  --revision REVISION   Commit to tag (default: origin/main)
  --push                Push the tag to the remote (default: local only)
  --skip-fetch          Do not fetch tags from the remote first
  --help                Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --revision)
      REVISION="${2:?missing revision}"
      shift 2
      ;;
    --push)
      PUSH=1
      shift
      ;;
    --skip-fetch)
      SKIP_FETCH=1
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v git >/dev/null

# Fetch tags before computing the counter, or two people tagging on the same
# day both compute -1 and the second push is rejected. Fetching makes the
# collision visible here instead.
if [[ "$SKIP_FETCH" -eq 0 ]]; then
  git fetch --quiet --prune --tags "$REMOTE"
fi

TARGET_SHA="$(git rev-parse --verify "${REVISION}^{commit}")"
TARGET_SHA="${TARGET_SHA,,}"

if ! [[ "$TARGET_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: invalid target SHA: $TARGET_SHA" >&2
  exit 1
fi

# Same gate deploy-production.sh applies: only something already on main may
# be released, so a tag can never point at unreviewed work.
if git show-ref --verify --quiet "refs/remotes/$REMOTE/main"; then
  if ! git merge-base --is-ancestor "$TARGET_SHA" "refs/remotes/$REMOTE/main"; then
    echo "ERROR: $REVISION ($TARGET_SHA) is not an ancestor of $REMOTE/main." >&2
    echo "Only reviewed, merged commits can be released." >&2
    exit 1
  fi
fi

# A release tag is dated by when it was cut, in UTC. Local time would make the
# tag name depend on who ran the script.
TODAY="$(date -u +%Y.%m.%d)"

# Highest counter already used today. `git tag --list` with an exact glob, then
# a numeric max: sorting lexically would put -10 before -9.
HIGHEST=0
while read -r existing; do
  [[ -z "$existing" ]] && continue
  counter="${existing##*-}"
  [[ "$counter" =~ ^[0-9]+$ ]] || continue
  if (( counter > HIGHEST )); then
    HIGHEST="$counter"
  fi
done < <(git tag --list "v${TODAY}-*")

TAG="v${TODAY}-$(( HIGHEST + 1 ))"

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "ERROR: tag already exists locally: $TAG" >&2
  exit 1
fi

# Annotated, not lightweight: it carries the tagger and date, and `git
# describe` prefers it. Release tags are permanent records, never moved.
SUBJECT="$(git log -1 --format=%s "$TARGET_SHA")"
git tag -a "$TAG" "$TARGET_SHA" -m "Release $TAG

Commit: $TARGET_SHA
$SUBJECT"

echo "Created tag: $TAG -> $TARGET_SHA"
echo "  $SUBJECT"

if [[ "$PUSH" -eq 1 ]]; then
  git push "$REMOTE" "refs/tags/$TAG"
  echo "Pushed: $TAG"
else
  echo
  echo "Local only. To publish it:"
  echo "  git push $REMOTE refs/tags/$TAG"
fi

echo
echo "Deploy this tag (tag first, then build — see the header of this script):"
echo "  deploy/scripts/deploy-production.sh --revision $TAG"
