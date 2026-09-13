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
