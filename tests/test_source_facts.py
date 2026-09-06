"""Source facts are reproducible syntax, not another model's opinion."""
import json
from pathlib import Path

from app.llm.client import LLMClient
from app.scan import source_facts
from app.scan.llm_scan import build_prompt, fit_to_window
from app.scan.pipeline import run_scan
from tests.test_audit_llm_wiring import FakeLLM, make_zip


HELPER = b"import hmac as hm\ndef _secret_equals(a, b):\n    return hm.compare_digest(a, b)\n"


def test_ast_records_helper_location_and_alias_without_running_archive(tmp_path):
    marker = tmp_path / "must-not-exist"
    payload = HELPER + f"open({str(marker)!r}, 'w').write('executed')\n".encode()
    record = source_facts.collect_source_facts(make_zip({"repo/shared.py": payload}))
    assert record["facts"] == [{
        "kind": "python_compare_digest_syntax", "file": "repo/shared.py", "line": 3,
        "scope": "_secret_equals", "call": "hm.compare_digest", "import_module": "hmac", "import_line": 1,
    }]
    assert record["parsed_files"] == 1
    assert not marker.exists()
    assert "operands and runtime behaviour are not verified" in record["scope"]


def test_comments_strings_unrelated_methods_and_relative_imports_are_not_facts():
    record = source_facts.collect_source_facts(make_zip({"repo/a.py": b'''
from .hmac import compare_digest
# hmac.compare_digest(a, b)
text = "hmac.compare_digest(a, b)"
compare_digest(a, b)
other.compare_digest(a, b)
'''}))
    assert record["facts"] == []


def test_direct_import_and_nested_scope_are_locations_not_runtime_bindings():
    record = source_facts.collect_source_facts(make_zip({"repo/a.py": b'''
from secrets import compare_digest as same
def outer(same):
    def inner(a, b):
        return same(a, b)
'''}))
    assert record["facts"][0]["scope"] == "outer.inner"
    assert record["facts"][0]["import_module"] == "secrets"
    # Deliberate shadowing: the fact promises syntax only, never resolution.
    assert "Name binding" in record["scope"]


def test_coverage_gaps_are_recorded_and_fixture_facts_do_not_look_like_app_guards(monkeypatch):
    monkeypatch.setattr(source_facts, "MAX_FILE_BYTES", 150)
    record = source_facts.collect_source_facts(make_zip({
        "repo/a.py": HELPER, "repo/b.py": b"broken!", "repo/big.py": b"#" * 151,
        "repo/tests/c.py": HELPER, "repo/vendor/d.py": HELPER,
    }))
    assert record["parsed_files"] == 1
    assert record["excluded_files"] == 2
    assert record["limitations"] == ["file_size_or_path_limit", "unparseable_python"]
    monkeypatch.setattr(source_facts, "MAX_FILES", 1)
    limited = source_facts.collect_source_facts(make_zip({"a.py": HELPER, "b.py": HELPER}))
    assert limited["limitations"] == ["scan_budget_reached"]


def test_fact_and_prompt_budgets_preserve_valid_records(monkeypatch):
    monkeypatch.setattr(source_facts, "MAX_FACTS", 2)
    record = source_facts.collect_source_facts(make_zip({"a.py": HELPER * 4}))
    assert len(record["facts"]) == 2
    assert record["limitations"] == ["fact_limit_reached"]
    limit = len(source_facts.facts_prompt(record)) - 1
    context = source_facts.facts_prompt(record, max_chars=limit)
    assert len(context) <= limit
    assert "prompt_fact_limit" in context
    json.loads(context[context.index('{'):])
    files = [("a.py", "x = 1\n" * 100), ("b.py", "x = 2\n" * 100)]
    window = len(build_prompt(files[:1], "auth", context))
    selected, prompt = fit_to_window(files, "auth", window, context)
    assert len(prompt) <= window
    assert selected == files[:1]
    assert context in prompt
    assert source_facts.facts_prompt(record, max_chars=10) == ""


def test_same_static_fact_record_in_free_and_paid_scan_and_model_receives_index():
    data = make_zip({"repo/shared.py": HELPER, "repo/auth.py": b"from shared import _secret_equals\n"}).getvalue()
    class RecordingLLM(FakeLLM):
        calls = []

        def complete(self, system, user, **kwargs):
            self.calls.append((system, user))
            return super().complete(system, user, **kwargs)

    client = RecordingLLM(response="[]")
    free = run_scan(data, LLMClient(providers=[]))
    paid = run_scan(data, client, llm_rubrics=("auth",))
    assert free["score"]["scan_manifest"]["source_facts"] == paid["score"]["scan_manifest"]["source_facts"]
    assert paid["score"]["scan_manifest"]["source_facts"]["facts"]
    assert len(client.calls) == 1  # No new model call for fact collection.
    assert "Source syntax index" in client.calls[0][1]
    assert "_secret_equals" in client.calls[0][1]


def test_real_shared_helper_is_located_without_importing_it():
    path = Path(__file__).resolve().parents[1] / "app/routes/_shared.py"
    record = source_facts.collect_source_facts(make_zip({"app/routes/_shared.py": path.read_bytes()}))
    fact = next(f for f in record["facts"] if f["scope"] == "_secret_equals")
    assert fact["call"] == "hmac.compare_digest"
    assert "hmac.compare_digest" in path.read_text().splitlines()[fact["line"] - 1]
