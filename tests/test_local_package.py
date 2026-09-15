"""Packaging boundaries: import relocation must preserve source semantics."""
import ast
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('local_builder', ROOT / 'scripts/build_local_package.py')
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)


def test_relocation_preserves_evidence_strings_urls_and_unicode_positions():
    source = '''"""from app.scan is evidence, not an import."""
label = "кириллица"; from app.scan.version import AUDIT_ENGINE_VERSION
from app.scan import static as stage
fn = optional_native_function("app.scan.cookie_flags", "scan_cookie_flags")
url = "https://raw.githubusercontent.com/aiagent2046-coder/shipit/main/app/data/cve-catalog.json"
'''
    result = builder.relocate(source)
    tree = ast.parse(result)
    assert [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)] == [
        'drydock_local.scan.version', 'drydock_local.scan']
    assert 'optional_native_function("drydock_local.scan.cookie_flags"' in result
    assert '"""from app.scan is evidence, not an import."""' in result
    assert '/main/app/data/cve-catalog.json' in result
    assert source.count('\n') == result.count('\n')


def test_offline_closure_cannot_silently_add_a_server_dependency(tmp_path):
    app = tmp_path / 'app'
    app.mkdir()
    (app / '__init__.py').write_text('')
    (app / 'local_cli.py').write_text('from app.main import app\n')
    with pytest.raises(ValueError, match='offline boundary'):
        builder.source_files(tmp_path)
    (app / 'local_cli.py').write_text('import httpx\n')
    with pytest.raises(ValueError, match='external dependency'):
        builder.source_files(tmp_path)
    (app / 'local_cli.py').write_text('from app.scan.pipeline import run_scan\n')
    with pytest.raises(ValueError, match='Server orchestration'):
        builder.source_files(tmp_path)


def test_new_dynamic_imports_cannot_escape_relocation():
    source = 'from importlib import import_module\nvalue = import_module("app.scan.other")'
    with pytest.raises(ValueError, match='dynamic application import'):
        builder.imports(ast.parse(source), ROOT)
    with pytest.raises(ValueError, match='must be a literal'):
        builder.imports(ast.parse('optional_native_function(module_name, "check")'), ROOT)


def test_real_closure_and_runtime_lock_are_complete():
    files = builder.source_files(ROOT)
    names = {p.relative_to(ROOT).as_posix() for p in files}
    assert {'app/local_cli.py', 'app/local_store.py', 'app/scan/cookie_flags.py',
            'app/scan/recommendations.py', 'app/sca/resolved_locks.py'} <= names
    assert not names & {'app/main.py', 'app/db.py', 'app/scan/pipeline.py', 'app/scan/llm_scan.py'}
    lock, pins = builder.locked_requirements(ROOT, builder.DEPENDENCIES)
    assert len(pins) == 4
    assert '--hash=sha256:' in lock
    for path in files:
        relocated = builder.relocate(path.read_text())
        ast.parse(relocated)


def test_missing_hashes_fail_before_build(tmp_path):
    (tmp_path / 'requirements.txt').write_text('pyyaml==6.0.3\n')
    with pytest.raises(ValueError, match='Missing runtime hashes'):
        builder.locked_requirements(tmp_path, {'pyyaml'})


@pytest.mark.parametrize('source', [
    'import importlib; module = importlib.import_module("app.main")',
    'from importlib import import_module as load; module = load("app.main")',
    'import_module(name)',
    'from builtins import __import__ as load; module = load("app.main")',
])
def test_dynamic_import_spellings_require_explicit_review(source):
    with pytest.raises(ValueError, match='dynamic application import'):
        builder.imports(ast.parse(source), ROOT)


def test_multiline_import_relocation_preserves_line_numbers():
    source = 'from ' + '\\\n' + ' app.scan.version import AUDIT_ENGINE_VERSION\n'
    result = builder.relocate(source)
    assert ast.parse(result).body[0].module == 'drydock_local.scan.version'
    assert result.count('\n') == source.count('\n')
