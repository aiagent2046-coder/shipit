# Bundled runtime and source

Drydock source is distributed under AGPL-3.0-or-later; see LICENSE.txt and
https://github.com/aiagent2046-coder/shipit/tree/main/browser .
The engine-files.json artifact includes the exact Python modules in this build.

Pyodide 314.0.6 is distributed under MPL-2.0. Source, license and bundled library
notices: https://github.com/pyodide/pyodide/tree/314.0.6 .
Pyodide incorporates CPython and other runtime components under their respective
licenses. CPython 3.14.2 license and acknowledgements:
https://docs.python.org/3.14/license.html .

PyYAML 6.0.3 is distributed under the MIT license. Its wheel retains its package
metadata and license files. Source and license:
https://github.com/yaml/pyyaml/tree/6.0.3 .

The build manifest records runtime versions and engine SHA-256. Package lock
integrity and the runtime catalog's PyYAML SHA-256 pin the downloaded artifacts.

Native parser wheels (source URLs and hashes in native-manifest.json):

- tree-sitter 0.26.0, MIT: https://github.com/tree-sitter/py-tree-sitter/tree/v0.26.0
- tree-sitter-typescript 0.23.2, MIT: https://github.com/tree-sitter/tree-sitter-typescript/tree/v0.23.2
- tree-sitter-javascript 0.25.0, MIT: https://github.com/tree-sitter/tree-sitter-javascript/tree/v0.25.0
- pglast 8.4, GPL-3.0-or-later, copyright Lele Gaifax:
  https://github.com/lelit/pglast/tree/v8.4 . Includes libpg_query (BSD-3-Clause)
  and PostgreSQL 18.4 parser sources (PostgreSQL license).

Complete parser license texts are distributed in licenses/. Tree-sitter wheel
metadata also retains its licenses. The pglast source distribution omits a full
GPL text; licenses/pglast-GPL-3.txt supplies it with this distribution. Source
archives for every wheel and the seven unmodified TypeScript headers are linked
by exact version and SHA-256 in native-manifest.json. Build instructions are in
browser/native/README.md and browser/scripts/rebuild-native.py in this repository.
No parser source algorithms were modified for these builds.

## Dependency advisory knowledge snapshot

The offline package catalog is derived from the CVE List maintained by the CVE
Program: https://github.com/CVEProject/cvelistV5. Source commit, timestamp, and
selection counters are preserved in the catalog and scan reports. Redistribution
and use of the source records are subject to the CVE Program Terms of Use:
https://www.cve.org/Legal/TermsOfUse. This catalog is a transformed subset, not the
complete CVE List; inclusion does not imply endorsement by the CVE Program.

The snapshot also includes a transformed subset of the GitHub Advisory
Database's `advisories/github-reviewed` records for npm and PyPI:
https://github.com/github/advisory-database . The database is licensed under
CC-BY-4.0. Each compiled snapshot records the exact source commit and selection
counters. Inclusion identifies GitHub curator review at that source revision; it
does not imply endorsement by GitHub or establish application exploitability.
