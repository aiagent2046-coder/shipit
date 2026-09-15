#!/usr/bin/env bash
# Install an unpacked, reviewed local-package artifact without contacting an index.
set -Eeuo pipefail
bundle_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install_dir="${1:-$HOME/.local/share/drydock/venv}"
python_bin="${PYTHON:-python3}"
"$python_bin" -c 'import os, sys; assert os.name == "posix" and sys.version_info >= (3, 12), "Requires Linux/macOS and Python 3.12+"'
if [[ -e "$install_dir" ]]; then
  echo "Destination already exists: $install_dir; choose a new directory." >&2
  exit 2
fi
"$python_bin" -m venv "$install_dir"
"$install_dir/bin/python" -m pip --isolated --disable-pip-version-check install \
  --no-index --only-binary=:all: --find-links "$bundle_dir/wheelhouse" \
  --require-hashes -r "$bundle_dir/install.txt"
"$install_dir/bin/python" -m pip --isolated --disable-pip-version-check check
printf '\nInstalled. Start with:\n  %q scan /path/to/project\n' "$install_dir/bin/drydock-local"
