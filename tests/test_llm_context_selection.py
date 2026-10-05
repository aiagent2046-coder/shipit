"""Context cost, source-coordinate and private accounting integration contracts."""
import io
import json
import zipfile

import httpx

from app.llm.client import LLMClient, Provider
from app.report.evidence import manifest_rows
from app.scan import llm_scan
from app.scan.manifest import scan_manifest
from app.scan.prompt_context import PromptExcerpt
from app.scan.secrets import is_non_production_path


def archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def client(answer="[]"):
    return LLMClient(
        providers=[Provider("openai_compat", "https://api.aitunnel.ru/v1", "synthetic", "claude-sonnet-4.6")],
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={
            "model": "claude-sonnet-4.6", "usage": {"prompt_tokens": 100, "completion_tokens": 4,
                                                       "cost_rub": "0.12"},
            "choices": [{"finish_reason": "stop", "message": {"content": answer}}],
        })),
    )


def test_unrelated_tests_cannot_displace_production_and_related_tests_are_bounded():
    files = [("src/ui/Login.tsx", "export const login = () => useEffect(() => render());\n" * 80),
             ("tests/Login.test.tsx", "test('login', () => useEffect(() => render()));\n" * 100),
             *[(f"tests/Noise{i}.test.tsx", "useEffect render fetch " * 100) for i in range(100)]]
    selected = llm_scan.select_files(files, "web", 20_000)
    names = [n for n, _ in selected]
    assert names[0] == "src/ui/Login.tsx"
    assert "tests/Login.test.tsx" in names
    assert not any("Noise" in n for n in names)
    assert sum(len(t) for n, t in selected if is_non_production_path(n)) <= 2000
    assert sum(len(t) for _, t in selected) <= 20_000
    assert selected == llm_scan.select_files(list(reversed(files)), "web", 20_000)


def test_migrations_remain_production_and_unrelated_support_does_not_create_a_review():
    files = [("tests/migrations/auth.sql", "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n"),
             ("tests/noise.py", "token = 'fixture'\n")]
    assert [n for n, _ in llm_scan.select_files(files, "auth")] == [files[0][0]]
    assert llm_scan.select_files([("src/main.py", "x = 1"), files[1]], "auth") == []


def test_test_only_repository_is_reported_as_such():
    buf = archive({"tests/test_auth.py": "token = 'fixture'\n",
                   "pyproject.toml": '[project]\nname="demo"\n'})
    _, stats = llm_scan.run_llm_scan(buf, client(), rubrics=("auth",))
    assert stats.calls == 1
    manifest = scan_manifest(buf.getvalue(), "test", {}, vars(stats), None)
    assert manifest["llm_selection_scope"] == "nonproduction_only"
    rows = dict(manifest_rows({"scan_manifest": manifest}))
    assert "not a review of production code" in rows["Model selection scope"]


def test_late_source_quote_keeps_its_original_coordinate_and_partial_scope():
    source = ("def unrelated():\n    return " + repr("x" * 50_000) + "\n"
              "\ndef authenticate(token):\n    return jwt.decode(token)\n")
    path = "src/auth.py"
    selected = llm_scan.select_files([(path, source)], "auth")
    assert isinstance(selected[0][1], PromptExcerpt)
    assert "5\t    return jwt.decode(token)" in llm_scan.build_prompt(selected, "auth")
    finding = dict(file=path, line_start=5, line_end=5, evidence="jwt.decode(token)",
                   severity="high", confidence=.8, title="Review decoder", explanation="Verify signature checking")
    assert llm_scan.verify_finding(finding, {path: source})
    marker_finding = {**finding, "evidence": "omitted original lines"}
    assert not llm_scan.verify_finding(marker_finding, {path: source})
    buf = archive({path: source})
    _, stats = llm_scan.run_llm_scan(buf, client(), rubrics=("auth",), passes=2)
    assert stats.partially_submitted_files == (path,)
    manifest = scan_manifest(buf.getvalue(), "test", {}, vars(stats), None)
    assert manifest["llm_partially_submitted_files"] == 1
    assert dict(manifest_rows({"scan_manifest": manifest}))["Files sent partially in at least one request"] == "1"
    assert [a["excerpt_files"] for a in stats.provider_attempts] == [1, 1]


def test_private_diagnostics_distinguish_embedded_empty_from_direct_array():
    _, stats = llm_scan.run_llm_scan(archive({"src/auth.py": "token = 1\n"}),
                                   client("Private answer text: []"), rubrics=("auth",))
    attempt = stats.provider_attempts[0]
    assert attempt["cost_rub"] == "0.12"
    assert attempt["answer_status"] == "empty_array"  # Legacy admission is unchanged.
    assert attempt["response_envelope"] == "embedded_array"
    assert attempt["direct_array_items"] is None
    assert attempt["response_chars"] == len("Private answer text: []")
    assert attempt["prompt_chars"] == stats.prompt_chars
    assert attempt["selected_content_chars"] == len("token = 1\n")
    assert "Private answer" not in json.dumps(attempt)
    manifest = scan_manifest(archive({"src/auth.py": "token = 1\n"}).getvalue(), "test", {}, vars(stats), None)
    assert "response_envelope" not in json.dumps(manifest)
    assert "provider_attempts" not in manifest
