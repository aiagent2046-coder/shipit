"""Build test inputs and native expectations; never included in public assets."""
import base64
import io
import zipfile
import json
import importlib.abc
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# A fresh process supplies the partial profile for the asset-failure test.
# Normal WASM corpus comparisons use the fully installed native profile.
if "--portable" in sys.argv:
    class NoNative(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in {
                "tree_sitter", "tree_sitter_typescript", "tree_sitter_javascript", "pglast",
            }:
                raise ModuleNotFoundError("Unavailable in browser profile", name=fullname)

    sys.meta_path.insert(0, NoNative())

from app.scan.browser import ScanSession, scan_archive  # noqa: E402
from tests.detectors.conftest import build_archive, discover_cases, load_expected  # noqa: E402
from parser_probes import probe_parsers  # noqa: E402


def main():
    if "--portable" in sys.argv:
        print(json.dumps([scan_archive(build_archive(path).getvalue())
                          for _, _, path in discover_cases()]))
        return
    portable = json.loads(subprocess.run(
        [sys.executable, __file__, "--portable"], check=True, capture_output=True, text=True,
    ).stdout)
    cases = []
    for index, (rule, polarity, directory) in enumerate(discover_cases()):
        data = build_archive(directory).getvalue()
        result = scan_archive(data)
        cases.append({"id": f"{rule}/{polarity}/{directory.name}", "rule": rule,
                      "polarity": polarity, "archive": base64.b64encode(data).decode(),
                      "expected": load_expected(directory), "native": result, "portable": portable[index]})
    out = Path(sys.argv[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cases))
    (out.parent / 'parser-probes.json').write_text(json.dumps(probe_parsers()))
    (out.parent / 'parser-probes.py').write_text((Path(__file__).parent / 'parser_probes.py').read_text())
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for index in range(400):
            z.writestr(f'src/module{index}.js', 'export const value = true;')
        z.writestr('src/tail.js', 'element.innerHTML = untrusted;')
        z.writestr('src/broken.js', 'const broken = [;')
    session = ScanSession(archive.getvalue())
    continuation = {"archive": base64.b64encode(archive.getvalue()).decode(),
                    "initial": session.result(), "final": session.continue_scan()}
    (out.parent / 'continuation.json').write_text(json.dumps(continuation))
    print(f"Wrote {len(cases)} native corpus expectations to {out}")


if __name__ == "__main__":
    main()
