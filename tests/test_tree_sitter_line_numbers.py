"""Native parser regressions run in a child so a SIGSEGV cannot kill pytest."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("scanner", ["operations", "react"])
@pytest.mark.parametrize("padding", [300, 1000])
def test_scanners_preserve_large_line_numbers_without_corrupting_memory(scanner, padding):
    # In tree-sitter 0.26.0 Point.row returns a borrowed PyLong reference.
    # Small fixtures hide the bug in CPython's cached integers; larger rows
    # can corrupt unrelated nodes and terminate the entire audit worker.
    script = r'''
import io
import json
import sys
import zipfile

try:
    import resource
except ImportError:
    pass
else:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

from app.scan.source_facts import collect_source_facts
from app.scan.syntax_claims import SyntaxVerifier

scanner, padding = sys.argv[1], int(sys.argv[2])
if scanner == "operations":
    source = "\n" * padding + (
        "async function request(input: string) { return fetch(input); }\n"
        "request(`${API_BASE_URL}/private-path-must-not-appear`);\n"
    )
else:
    source = 'import {useState} from "react";\n' + "\n" * (padding - 1) + (
        "export function Component({ok}) {\n"
        "  const [x] = useState(0);\n"
        "  if (!ok) return null;\n"
        "  return <div>{x}</div>;\n"
        "}\n"
    )
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as archive:
    archive.writestr("src/Component.tsx", source)
payload = buf.getvalue()

for _ in range(20):
    archive = io.BytesIO(payload)
    if scanner == "operations":
        facts = collect_source_facts(archive)
        record, = facts["operations"]["records"]
        assert record["line"] == padding + 1, record
        assert record["scope"] == "request", record
        assert f"Same-file call spelling at line {padding + 2}:" in record["detail"], record
        assert "template_string; names: API_BASE_URL" in record["detail"], record
        assert "must-not-appear" not in json.dumps(facts)
    else:
        result = SyntaxVerifier(archive).check({
            "file": "src/Component.tsx", "line_start": padding + 2,
            "line_end": padding + 3,
            "title": "useState calls follow an early return — hook order changes",
        })
        assert result["result"] == "contradicted", result
        assert (result["line_start"], result["line_end"]) == (padding + 1, padding + 5), result
print("ok")
'''
    result = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", script, scanner, str(padding)],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONMALLOC": "debug"},
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert result.stdout.strip() == "ok"
