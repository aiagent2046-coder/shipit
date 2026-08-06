#!/usr/bin/env bash
set -Eeuo pipefail

SYSTEMCTL="${SHIPIT_SYSTEMCTL:-systemctl}"
SYSTEMD_ANALYZE="${SHIPIT_SYSTEMD_ANALYZE:-systemd-analyze}"

UNIT_RELATIVE="${SHIPIT_FIXPACK_UNIT_RELATIVE:-deploy/systemd/shipit-fixpack.service}"
UNIT_DEST="${SHIPIT_FIXPACK_UNIT_DEST:-/etc/systemd/system/shipit-fixpack.service}"

usage() {
  cat <<'USAGE'
Usage:
  sync-release-systemd-unit.sh --release RELEASE_DIRECTORY

Validates and atomically installs the Fix Pack service unit belonging to
the specified immutable release, then reloads systemd.

The previous installed file is restored if daemon-reload fails.
USAGE
}

RELEASE=""

while (($#)); do
  case "$1" in
    --release)
      RELEASE="${2:?missing release directory}"
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

if [[ -z "$RELEASE" ]]; then
  echo "ERROR: --release is required" >&2
  exit 2
fi

SOURCE="$RELEASE/$UNIT_RELATIVE"
DEST_DIR="$(dirname "$UNIT_DEST")"
UNIT_NAME="$(basename "$UNIT_DEST")"

if [[ ! -d "$RELEASE" ]]; then
  echo "ERROR: release directory does not exist: $RELEASE" >&2
  exit 1
fi

if [[ ! -f "$SOURCE" ]]; then
  echo "ERROR: release unit is missing: $SOURCE" >&2
  exit 1
fi

command -v "$SYSTEMCTL" >/dev/null
command -v "$SYSTEMD_ANALYZE" >/dev/null
command -v install >/dev/null
command -v mktemp >/dev/null

"$SYSTEMD_ANALYZE" verify "$SOURCE"

mkdir -p "$DEST_DIR"

NEW_FILE="$(
  mktemp "$DEST_DIR/.${UNIT_NAME}.new.XXXXXX"
)"
OLD_FILE=""

cleanup() {
  if [[ -n "$NEW_FILE" ]]; then
    rm -f -- "$NEW_FILE"
  fi

  if [[ -n "$OLD_FILE" ]]; then
    rm -f -- "$OLD_FILE"
  fi
}

trap cleanup EXIT

install \
  --mode=0644 \
  "$SOURCE" \
  "$NEW_FILE"

if [[ -e "$UNIT_DEST" ]]; then
  OLD_FILE="$(
    mktemp "$DEST_DIR/.${UNIT_NAME}.old.XXXXXX"
  )"

  cp -a -- "$UNIT_DEST" "$OLD_FILE"
fi

mv -f -- "$NEW_FILE" "$UNIT_DEST"
NEW_FILE=""

if ! "$SYSTEMCTL" daemon-reload; then
  echo \
    "ERROR: systemd reload failed; restoring the previously installed unit" \
    >&2

  if [[ -n "$OLD_FILE" ]]; then
    mv -f -- "$OLD_FILE" "$UNIT_DEST"
    OLD_FILE=""
  else
    rm -f -- "$UNIT_DEST"
  fi

  if ! "$SYSTEMCTL" daemon-reload; then
    echo \
      "ERROR: systemd reload also failed after restoring the previous unit" \
      >&2
  fi

  exit 1
fi

echo "Installed release unit: $SOURCE"
echo "Systemd unit target:    $UNIT_DEST"
