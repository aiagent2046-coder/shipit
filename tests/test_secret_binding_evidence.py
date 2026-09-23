"""A named secret requires a reaching literal, not a namesake elsewhere."""

import io
import json
from pathlib import Path
import subprocess
import sys
import textwrap
import zipfile

import pytest

from app.scan.secrets import scan_secrets


def _assignments(source, name="app/config.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(name, source)
    buf.seek(0)
    return [f for f in scan_secrets(buf) if f.rule_id == "generic-assignment"]


@pytest.mark.parametrize("source", [
    'def unrelated():\n    holder = "ordinaryliteralvalue"\n'
    'def connect(holder):\n    api_key = holder\n',
    'import os\nholder = "ordinaryliteralvalue"\n'
    'holder = os.environ["API_KEY"]\napi_key = holder\n',
    'api_key = holder\nholder = "ordinaryliteralvalue"\n',
    '\"\"\"\nholder = "ordinaryliteralvalue"\n\"\"\"\n'
    'def connect(holder):\n    api_key = holder\n',
    'if condition:\n    holder = "ordinaryliteralvalue"\napi_key = holder\n',
])
def test_unproven_python_reference_does_not_become_a_hardcoded_secret(source):
    assert not _assignments(source)


@pytest.mark.parametrize("source", [
    'function unused() {\n const holder = "ordinaryliteralvalue";\n}\n'
    'function connect(holder) {\n const api_key = holder;\n}\n',
    'let holder = "ordinaryliteralvalue";\n'
    'holder = process.env.API_KEY;\nconst api_key = holder;\n',
    'const api_key = holder;\nconst holder = "ordinaryliteralvalue";\n',
    '/*\nconst holder = "ordinaryliteralvalue";\n*/\nconst api_key = holder;\n',
    'if (condition) {\nvar holder = "ordinaryliteralvalue";\n}\n'
    'const api_key = holder;\n',
])
def test_unproven_js_reference_does_not_become_a_hardcoded_secret(source):
    assert not _assignments(source, "app/config.js")


@pytest.mark.parametrize("name,source,line", [
    ("app/config.py", 'def configure():\n    holder = "ordinaryliteralvalue"\n'
     '    api_key = holder\n', 3),
    ("app/config.js", 'function configure() {\n const holder = "ordinaryliteralvalue";\n'
     ' const api_key = holder;\n}\n', 3),
])
def test_adjacent_local_literal_is_reported_without_exposing_its_value(name, source, line):
    findings = _assignments(source, name)
    assert len(findings) == 1
    assert findings[0].line == line
    assert "ordinaryliteralvalue" not in repr(findings[0])


@pytest.mark.parametrize("missing", ["tree_sitter", "tree_sitter_typescript"])
def test_native_free_js_keeps_literal_findings_and_marks_unresolved_aliases(missing):
    # A fresh interpreter prevents cached parser modules from hiding the
    # browser's genuinely missing native dependency.
    code = textwrap.dedent('''
        import importlib.abc, io, json, sys, zipfile
        class NoNative(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname.split(".")[0] == sys.argv[1]:
                    raise ModuleNotFoundError("native dependency absent", name=fullname)
        sys.meta_path.insert(0, NoNative())
        from app.scan.secrets import scan_secrets
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("app/literal.js", 'const api_key = "ordinaryliteralvalue";\\n')
            archive.writestr("app/alias.js", 'const holder = "ordinaryliteralvalue";\\n'
                             'const api_key = holder;\\n')
        data.seek(0)
        coverage = {}
        findings = scan_secrets(data, coverage=coverage)
        print(json.dumps({"findings": [vars(f) for f in findings], "coverage": coverage}))
    ''')
    completed = subprocess.run(
        [sys.executable, "-c", code, missing], cwd=Path(__file__).resolve().parents[1],
        text=True, capture_output=True, check=True,
    )
    result = json.loads(completed.stdout)
    assignments = [f for f in result["findings"] if f["rule_id"] == "generic-assignment"]
    assert [(f["file"], f["line"]) for f in assignments] == [("app/literal.js", 1)]
    assert "ordinaryliteralvalue" not in completed.stdout
    assert result["coverage"]["files_scanned"] == 2
    assert result["coverage"]["limitations"] == ["javascript_alias_resolution_unavailable"]
