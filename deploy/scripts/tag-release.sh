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

# --- failure must be loud ---------------------------------------------------
# This script died in complete silence three times in two days. Its first
# action was `git fetch --quiet --prune --tags`; a stale local tag whose name
# matched a different remote tag object failed the fetch; --quiet swallowed
# git's one line naming the problem; and set -e exited before anything was
# printed. Piped through `| tail`, the operator saw a command that ran,
# printed nothing, and appeared to succeed — on the script that decides what
# production is called, whose own header warns that a missing tag leaves
# /version reporting a bare SHA. Under set -e, a step that cannot name its
# own failure reads as success.
on_error() {
  local status=$?
  echo "tag-release: FAILED (exit $status) at: ${BASH_COMMAND}" >&2
  echo "tag-release: nothing this run printed above the line was completed." >&2
  exit "$status"
}
trap on_error ERR

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
#
# The fetch has one expected failure: " ! [rejected] ... would clobber
# existing tag", which is what a second machine holds whenever two people
# (or one person and one agent) tagged the same release — same tag name,
# same commit, different tag objects. That case is resolved here, loudly:
# the local copy is a stale duplicate and the remote's is canonical, so
# deleting it loses nothing and the refetch restores it. The case it must
# NOT resolve is the same name on DIFFERENT commits — that is a
# disagreement about what was released, and a script has no business
# picking a side in it.
#
# LC_ALL=C because the resolution parses git's message text; a localized
# "rejected" would silently take the unrecognised-failure path instead.
fetch_tags() {
  local out
  if out="$(LC_ALL=C git fetch --prune --tags "$REMOTE" 2>&1)"; then
    # A fetch that BRINGS tags prints lines. That is news, not an error.
    [[ -n "$out" ]] && printf '%s\n' "$out"
    return 0
  fi
  printf '%s\n' "$out" >&2

  local stale
  stale="$(printf '%s\n' "$out" | sed -n \
    's/^ ! \[rejected\][[:space:]]*\([^[:space:]]*\).*would clobber existing tag.*/\1/p')"
  # No message of our own for an unrecognised failure: git's is already
  # above, and the ERR trap names the step. A line here would be a second
  # copy of the trap's job -- unkillable by any test, and mutation-checking
  # this script is how its last silent death was supposed to be caught.
  [[ -z "$stale" ]] && return 1

  local name local_sha remote_sha
  while read -r name; do
    [[ -z "$name" ]] && continue
    local_sha="$(git rev-parse --verify "refs/tags/${name}^{commit}")"
    # The peeled ref first (annotated tags), the plain ref as fallback
    # (lightweight ones).
    remote_sha="$(git ls-remote "$REMOTE" "refs/tags/${name}^{}" | cut -f1)"
    [[ -z "$remote_sha" ]] && \
      remote_sha="$(git ls-remote "$REMOTE" "refs/tags/${name}" | cut -f1)"
    if [[ -n "$remote_sha" && "$local_sha" == "$remote_sha" ]]; then
      echo "tag-release: local tag $name is a stale duplicate of $REMOTE's" \
           "(same commit ${local_sha:0:7}, different tag object — the same" \
           "release was tagged twice). Replacing it with $REMOTE's." >&2
      git tag -d "$name" >/dev/null
    else
      echo "tag-release: local tag $name points at ${local_sha:0:7} but" \
           "$REMOTE has ${remote_sha:0:7} under that name." >&2
      echo "tag-release: that is a disagreement about what was released;" \
           "refusing to pick a side." >&2
      echo "tag-release: inspect both (git show $name; git ls-remote $REMOTE" \
           "refs/tags/$name), delete the wrong one, and re-run." >&2
      return 1
    fi
  done <<< "$stale"

  git fetch --prune --tags "$REMOTE"
}

if [[ "$SKIP_FETCH" -eq 0 ]]; then
  fetch_tags
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
