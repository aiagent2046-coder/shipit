# Native Python parsers compiled to WASM

These four wheels are runtime assets, not host Python wheels. The normal web
build verifies their hashes and ABI against `manifest.json`, then copies them
into the same-origin Pyodide package catalog. No CDN is used at scan time.

Toolchain: Python 3.14.2, Pyodide/xbuildenv 314.0.6, pyodide-build 0.39.0,
Emscripten 5.0.3, ABI `2026_0`. The tree-sitter wheels were built using setuptools
84.0.0; pglast 8.4 uses its source-pinned setuptools 83.0.0 and Cython 3.2.8.
All use `SOURCE_DATE_EPOCH=1789257600`. The manifest records source archive
and wheel SHA-256 values separately.

The TypeScript 0.23.2 PyPI sdist omits `common/scanner.h` and the six
`tree_sitter/*.h` headers. These are copied without modification from the
official npm package of the same version. Its hash and exact seven-file
allowlist are in the manifest. All parser C sources are otherwise unchanged.
Pglast uses its bundled generated C; Pyodide's compiler/archive wrappers also
build the nested libpg_query library. No host-native static archive is reused.

## Rebuild on Linux

Use a dedicated Python 3.14.2 environment, a C/C++ build toolchain, make and curl.
Allow several GB for the compiler and source trees:

```bash
python3.14 -m venv /tmp/drydock-wasm-env
source /tmp/drydock-wasm-env/bin/activate
pip install pyodide-build==0.39.0
export PYODIDE_XBUILDENV_PATH=/tmp/drydock-xbuildenv
pyodide xbuildenv install 314.0.6
TAR_OPTIONS=--no-same-owner pyodide xbuildenv install-emscripten
source "$PYODIDE_XBUILDENV_PATH/314.0.6/emsdk/emsdk_env.sh"
python browser/scripts/rebuild-native.py /tmp/drydock-rebuilt
```

The output directory must not exist. Source downloads are hash-checked before
extraction. Logs and rebuilt wheels stay in that directory; the script does
not overwrite reviewed assets or update the manifest automatically. The tar
option only avoids preserving SDK archive ownership in restricted containers.

`rebuilt.json` compares wheel hashes with this release. Byte-for-byte
reproducibility is not claimed: build paths and isolated backend dependencies
can affect artifacts. Before replacing wheels, inspect any build changes,
update their hashes and run the native parser probes, full corpus parity and
Chromium workflow documented in `../README.md`. These are release gates even
if the rebuilt wheel hashes happen to match.

Source archives are linked directly in `manifest.json`; complete parser license
texts are in `licenses/`. Both ship with the static application.
