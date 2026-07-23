#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
  pwd
)"

if (($# == 0)); then
  set -- apply
fi

exec python3 \
  "${SCRIPT_DIR}/migration_manager.py" \
  "$@"
