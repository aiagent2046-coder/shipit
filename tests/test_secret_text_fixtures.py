"""Generated document text is retained as context, without hiding credentials."""

import builtins
from dataclasses import asdict
import io
import json
import zipfile

import pytest

from app.report.owner_roadmap import build_owner_roadmap
from app.report.plain_language import plain_fields
from app.scan.collapse import collapse_repeats
from app.scan.secrets import scan_secrets


TEXT = "VeryLongUnbrokenText"
SOURCE = """test('wraps all document text', async () => {
 const token='VeryLongUnbrokenText'.repeat(30),entries=[{record:2,text:token}];
 const text=await renderText(entries);
 assert.ok(text.replaceAll(' ','').includes(token));
});
"""


def scan(source=SOURCE, path="ctt/tests/pdf-edit.test.mjs"):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr(path, source)
    data.seek(0)
    return scan_secrets(data)


def generic(source=SOURCE, path="ctt/tests/pdf-edit.test.mjs"):
    findings = [f for f in scan(source, path) if f.rule_id == "generic-assignment"]
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize("path", [
    "ctt/tests/pdf-edit.test.mjs", "tests/pdf-edit.cjs", "tests/pdf-edit.js",
    "tests/pdf-edit.jsx", "tests/pdf-edit.ts", "tests/pdf-edit.tsx",
    "src/pdf-edit.test.mjs", "src/pdf-edit.spec.cjs",
])
def test_document_repeat_keeps_informational_candidate_and_exact_location(path):
    finding = generic(path=path)
    assert finding.context == "test_fixture"
    assert finding.severity == "low"
    assert finding.source_context["kind"] == "repeated_test_text"
    assert (finding.file, finding.line) == (path, 2)
    assert TEXT not in json.dumps(asdict(finding))


def test_unicode_prefix_does_not_move_the_source_binding():
    source = SOURCE.replace(" const token=", " const label='Абзац'; const token=")
    assert generic(source).source_context["kind"] == "repeated_test_text"


@pytest.mark.parametrize("path", [
    "src/pdf-edit.mjs", "scripts/pdf-edit.cjs", "tests/migrations/001.mjs",
])
def test_production_and_migration_paths_keep_the_original_candidate(path):
    finding = generic(path=path)
    assert finding.context != "test_fixture"
    assert not finding.source_context or finding.source_context.get("kind") != "repeated_test_text"


@pytest.mark.parametrize("source", [
    SOURCE.replace("text:token", "text:'another paragraph'"),
    SOURCE.replace(" const text=", " sendCredential(token);\n const text="),
    SOURCE.replace(" const text=", " const auth={authorization:token};\n const text="),
    SOURCE.replace(" const text=", " token+='suffix';\n const text="),
    SOURCE.replace(" const text=", " const capture=()=>token;\n const text="),
    SOURCE.replace(" const text=", " const capture={token};\n const text="),
    SOURCE.replace(".repeat(30)", ".repeat(count)"),
    SOURCE.replace(".repeat(30)", ".repeat(1)"),
    SOURCE.replace(".repeat(30)", ".repeat(2.5)"),
    SOURCE.replace(".repeat(30)", ".repeat(1000000000)"),
    SOURCE.replace("const token=", "let token="),
    SOURCE.replace("VeryLongUnbrokenText", "x7Kp2mQ9fLw3RnT6Yh2Vb8C4"),
    SOURCE + "function broken( {\n",
])
def test_unproven_or_credential_use_preserves_test_file_classification(source):
    finding = generic(source)
    assert finding.context == "test_file"
    assert not finding.source_context or finding.source_context.get("kind") != "repeated_test_text"


def test_a_provider_credential_is_retained_even_when_repeated_as_document_text():
    credential = "AKIA" + "A" * 16
    findings = scan(SOURCE.replace(TEXT, credential))
    provider = next(f for f in findings if f.rule_id == "aws-access-key-id")
    assignment = next(f for f in findings if f.rule_id == "generic-assignment")
    assert provider.context == assignment.context == "test_file"
    assert credential not in json.dumps([asdict(f) for f in findings])


def test_other_test_scope_does_not_supply_the_missing_text_use():
    source = """test('credentials', () => {
 const token='VeryLongUnbrokenText'.repeat(30);
 authorize(token);
});
test('document', () => {
 const token='AnotherLongTextValue'.repeat(30);
 const entries=[{text:token}];
});
"""
    findings = {f.line: f for f in scan(source) if f.rule_id == "generic-assignment"}
    assert findings[2].context == "test_file"
    assert findings[6].context == "test_fixture"


@pytest.mark.parametrize("missing", ["tree_sitter", "tree_sitter_typescript"])
def test_missing_native_parser_preserves_the_original_candidate(monkeypatch, missing):
    original = builtins.__import__

    def without_parser(name, *args, **kwargs):
        if name.split(".", 1)[0] == missing:
            raise ModuleNotFoundError("Native dependency unavailable", name=missing)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_parser)
    finding = generic()
    assert finding.context == "test_file"
    assert not finding.source_context or finding.source_context.get("kind") != "repeated_test_text"


@pytest.mark.parametrize("suffix", ["js", "mjs", "cjs"])
def test_js_declaration_has_no_duplicate_sql_credential_rule(suffix):
    findings = scan("const api_key='ordinarycredentialvalue';\n", f"app/config.{suffix}")
    assert [f.rule_id for f in findings] == ["generic-assignment"]


@pytest.mark.parametrize("suffix", ["mjs", "cjs"])
def test_sql_embedded_in_javascript_keeps_the_credential_assignment(suffix):
    source = 'const query="UPDATE config SET api_key=\'ordinarycredentialvalue\';";\n'
    findings = scan(source, f"app/config.{suffix}")
    assert {f.rule_id for f in findings} == {"generic-assignment", "sql-secret-assignment"}
    assert all(f.line == 1 for f in findings)


def test_report_explains_repeated_text_without_credential_rotation_task():
    record = asdict(generic()) | {"source": "static"}
    what, risk, fix = plain_fields(record)
    assert "text" in what.lower()
    assert "repeat" in (what + risk).lower()
    assert "rotate" not in fix.lower()
    tasks = build_owner_roadmap([record])["tasks"]
    assert "test-credential-review" not in {task["id"] for task in tasks}


def test_real_credential_candidate_still_generates_the_test_review_task():
    record = asdict(generic(SOURCE.replace(
        " const text=", " authenticate(token);\n const text="))) | {"source": "static"}
    tasks = build_owner_roadmap([record])["tasks"]
    assert "test-credential-review" in {task["id"] for task in tasks}


def test_fixture_explanation_survives_persisted_claim_evidence_replay():
    record = asdict(generic()) | {"source": "static"}
    expected = plain_fields(record)
    record["claim_evidence"] = {"version": 1, "source_context": record.pop("source_context")}
    restored = json.loads(json.dumps(record))
    assert plain_fields(restored) == expected
    assert "test-credential-review" not in {
        task["id"] for task in build_owner_roadmap([restored])["tasks"]
    }


@pytest.mark.parametrize("persisted", [False, True])
def test_collapse_keeps_text_context_separate_from_an_ordinary_identical_mask(persisted):
    fixture = asdict(generic()) | {"source": "static"}
    ordinary = asdict(generic(
        SOURCE.replace(" const text=", " authenticate(token);\n const text="),
        "tests/authentication.test.mjs",
    )) | {"source": "static"}
    assert fixture["masked"] == ordinary["masked"]
    assert ordinary["context"] == "test_file"
    records = [fixture, ordinary]
    if persisted:
        for record in records:
            record["claim_evidence"] = {"version": 1, "source_context": record.pop("source_context")}
        records = json.loads(json.dumps(records))
    collapsed = collapse_repeats(records)
    assert len(collapsed) == 2
    assert {record["file"] for record in collapsed} == {
        "ctt/tests/pdf-edit.test.mjs", "tests/authentication.test.mjs",
    }
    assert all("occurrence_count" not in record for record in collapsed)
    tasks = build_owner_roadmap(collapsed)["tasks"]
    review = next(task for task in tasks if task["id"] == "test-credential-review")
    assert [collapsed[index]["file"] for index in review["finding_indices"]] == [
        "tests/authentication.test.mjs",
    ]
