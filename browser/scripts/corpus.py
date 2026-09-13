"""Build test inputs and native expectations; never included in public assets."""
import base64
import json
import importlib.abc
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# A second fresh process supplies native-Python expectations for the exact
# partial browser profile. This catches losses within supported checks, while
# the fully installed profile quantifies the explicitly missing capabilities.
if "--portable" in sys.argv:
    class NoNative(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in {
                "tree_sitter", "tree_sitter_typescript", "tree_sitter_javascript", "pglast",
            }:
                raise ModuleNotFoundError("Unavailable in browser profile", name=fullname)

    sys.meta_path.insert(0, NoNative())

from app.scan.browser import scan_archive  # noqa: E402
from tests.detectors.conftest import build_archive, discover_cases, load_expected  # noqa: E402


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
    print(f"Wrote {len(cases)} native corpus expectations to {out}")


if __name__ == "__main__":
    main()
