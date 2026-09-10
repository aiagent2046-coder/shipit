"""SARIF output: valid against the real schema, and the same findings as the
JSON report.

Two claims have to hold at once, and they are different claims:

1. a SARIF consumer will ACCEPT the document -- checked against the OASIS
   schema that GitHub and VS Code validate with, checked in under
   tests/fixtures/ (see the SOURCE note beside it);
2. the document describes exactly the findings this audit produced -- no
   invention, no silent omission, no reordering that loses a row.

A test that only did (1) would pass on an empty runs[].results; a test that only
did (2) would pass on a shape nobody can consume.
"""
from __future__ import annotations

import json
import pathlib

import jsonschema
import pytest

from app.llm.client import LLMClient
from app.report.plain_language import PLAIN
from app.report.sarif import (FINGERPRINT_KEY, LEVELS, SARIF_VERSION, build_sarif,
                              fingerprint, render_sarif)
from app.sca.osv import OsvClient
from app.scan.pipeline import AUDIT_ENGINE_VERSION, run_scan
from tests.test_sca_stage import FakeTransport, LODASH_ADVISORY, make_zip

SCHEMA_PATH = pathlib.Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"

STATIC = {"rule_id": "no-dockerfile", "title": "No Dockerfile", "severity": "low",
          "confidence": 0.8, "category": "Deploy", "file": "", "line": 0,
          "explanation": "Nothing tells a deploy how to build this.",
          "fix_hint": "Add a Dockerfile."}
SECRET = {"rule_id": "generic-assignment", "title": "Hardcoded credential assignment",
          "severity": "high", "confidence": 0.9, "category": "Security",
          "file": "src/config.ts", "line": 12, "masked": "apiK****(39 chars)",
          "explanation": "A credential appears in the source.",
          "fix_hint": "Move it to an environment variable."}
SCA = {"rule_id": "dependency-known-vulnerability",
       "title": "8 known vulnerabilities in lodash 4.17.4", "severity": "critical",
       "confidence": 0.9, "category": "Security", "file": "package-lock.json",
       "line": 0, "explanation": "The lockfile resolves lodash to 4.17.4.",
       "fix_hint": "Upgrade to 4.18.0 or later."}
SPACED = {**SECRET, "file": "src/my config/keys.ts", "line": 3, "masked": "qrst****"}

ALL_FINDINGS = [STATIC, SECRET, SCA, SPACED]


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def validate(document: dict, schema: dict) -> None:
    jsonschema.validate(instance=document, schema=schema)


# -- the schema gate -------------------------------------------------------

def test_the_export_validates_against_the_oasis_sarif_schema(schema):
    validate(build_sarif(ALL_FINDINGS, engine_version=AUDIT_ENGINE_VERSION), schema)


def test_the_schema_gate_can_actually_fail(schema):
    """The control. A validator that accepts anything proves nothing, and this
    is the one test that keeps the one above from being decoration."""
    document = build_sarif(ALL_FINDINGS, engine_version=AUDIT_ENGINE_VERSION)
    document["runs"][0]["results"][0]["level"] = "severe"
    with pytest.raises(jsonschema.ValidationError):
        validate(document, schema)

    document = build_sarif(ALL_FINDINGS, engine_version=AUDIT_ENGINE_VERSION)
    del document["runs"][0]["results"][0]["message"]
    with pytest.raises(jsonschema.ValidationError):
        validate(document, schema)

    document = build_sarif(ALL_FINDINGS, engine_version=AUDIT_ENGINE_VERSION)
    document["version"] = "2.0"
    with pytest.raises(jsonschema.ValidationError):
        validate(document, schema)


def test_an_audit_with_nothing_to_report_is_still_a_valid_document(schema):
    document = build_sarif([], engine_version=AUDIT_ENGINE_VERSION)
    validate(document, schema)
    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []


# -- the same findings as the report ---------------------------------------

def findings_from_a_real_scan() -> tuple[list[dict], dict]:
    transport = FakeTransport([[{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}]],
                              {"GHSA-35jh-r3h4-6jhm": LODASH_ADVISORY})
    repo = make_zip({
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/lodash": {"version": "4.17.4"}}}),
    })
    scan = run_scan(repo, LLMClient(), sca_client=OsvClient(transport=transport))
    return scan["findings"], scan["score"]


def test_a_real_scan_exports_a_valid_document_with_the_same_rows(schema):
    findings, score = findings_from_a_real_scan()
    document = build_sarif(findings, engine_version=AUDIT_ENGINE_VERSION, score=score)
    validate(document, schema)

    exported = {(result["ruleId"], result["locations"][0]["physicalLocation"]
                 ["artifactLocation"]["uri"],
                 result["locations"][0]["physicalLocation"].get("region", {})
                 .get("startLine", 0))
                for result in document["runs"][0]["results"]}
    reported = {(str(f["rule_id"]), str(f.get("file") or ""),
                 f["line"] if isinstance(f.get("line"), int) else 0)
                for f in findings}
    assert exported == reported, "the export must describe the same findings"
    assert exported, "and the fixture must have produced some"


def test_every_rule_used_is_declared_and_indexed_consistently(schema):
    document = build_sarif(ALL_FINDINGS, engine_version=AUDIT_ENGINE_VERSION)
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == sorted({f["rule_id"] for f in ALL_FINDINGS})
    by_index = {index: rule["id"] for index, rule in enumerate(rules)}
    for result in run["results"]:
        assert by_index[result["ruleIndex"]] == result["ruleId"]


# -- severity, wording, fingerprints ---------------------------------------

@pytest.mark.parametrize("severity,level", [
    ("critical", "error"), ("high", "error"), ("medium", "warning"),
    ("low", "note"), ("unknown-severity", "warning"),
])
def test_severity_maps_onto_sarif_levels(severity, level):
    document = build_sarif([{**SECRET, "severity": severity}],
                           engine_version=AUDIT_ENGINE_VERSION)
    assert document["runs"][0]["results"][0]["level"] == level
    assert set(LEVELS.values()) <= {"error", "warning", "note", "none"}


def test_rule_metadata_comes_from_the_same_dictionary_the_report_uses():
    document = build_sarif([SECRET], engine_version=AUDIT_ENGINE_VERSION)
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    what, risk, _fix = PLAIN["generic-assignment"]
    assert rule["shortDescription"]["text"] == what
    assert rule["fullDescription"]["text"] == risk


def test_the_message_carries_the_plain_language_explanation():
    document = build_sarif([SECRET], engine_version=AUDIT_ENGINE_VERSION)
    text = document["runs"][0]["results"][0]["message"]["text"]
    assert SECRET["title"] in text
    assert SECRET["explanation"] in text


def test_a_finding_that_moves_down_a_file_keeps_its_identity():
    moved = {**SECRET, "line": 400}
    assert fingerprint(moved) == fingerprint(SECRET), (
        "a consumer deduping on this must not see a moved finding as new")


def test_a_changed_evidence_gets_a_new_identity():
    assert fingerprint({**SECRET, "masked": "zzzz****"}) != fingerprint(SECRET)
    assert fingerprint({**SECRET, "file": "src/other.ts"}) != fingerprint(SECRET)
    assert fingerprint({**SECRET, "rule_id": "sql-secret-assignment"}) != fingerprint(SECRET)


def test_fingerprints_are_published_under_our_own_key(schema):
    document = build_sarif(ALL_FINDINGS, engine_version=AUDIT_ENGINE_VERSION)
    validate(document, schema)
    for result in document["runs"][0]["results"]:
        assert set(result["partialFingerprints"]) == {FINGERPRINT_KEY}


# -- locations -------------------------------------------------------------

def test_a_finding_without_a_line_gets_no_region():
    document = build_sarif([STATIC, SCA], engine_version=AUDIT_ENGINE_VERSION)
    for result in document["runs"][0]["results"]:
        physical = result["locations"][0]["physicalLocation"]
        assert "region" not in physical, (
            "SARIF requires startLine >= 1; inventing one would point at the wrong line")


def test_a_finding_with_a_line_points_at_it():
    document = build_sarif([SECRET], engine_version=AUDIT_ENGINE_VERSION)
    physical = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["region"] == {"startLine": 12}
    assert physical["artifactLocation"]["uri"] == "src/config.ts"


def test_a_dotfile_path_is_kept_intact():
    """`lstrip("./")` strips CHARACTERS, so `.env` came out as `env` -- a
    location pointing at a file that does not exist, which is what a SARIF
    consumer matches results against. GitHub uses these paths."""
    for path, expected in [(".env", ".env"), ("..env", "..env"),
                           ("./.env", ".env"), ("/src/.env", "src/.env"),
                           ("./src/config.ts", "src/config.ts"),
                           ("src/config.ts", "src/config.ts")]:
        document = build_sarif([{**SECRET, "file": path, "line": 1}],
                               engine_version=AUDIT_ENGINE_VERSION)
        uri = document["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"]["artifactLocation"]["uri"]
        assert uri == expected, f"{path!r} became {uri!r}"


def test_a_path_that_is_not_a_uri_is_encoded():
    document = build_sarif([SPACED], engine_version=AUDIT_ENGINE_VERSION)
    uri = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"]
    assert uri == "src/my%20config/keys.ts"
    assert " " not in uri


# -- execution facts -------------------------------------------------------

def test_the_invocation_records_what_was_and_was_not_examined():
    _findings, score = findings_from_a_real_scan()
    document = build_sarif([SCA], engine_version=AUDIT_ENGINE_VERSION, score=score)
    invocation = document["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["properties"]["engineVersion"] == AUDIT_ENGINE_VERSION
    assert invocation["properties"]["basis"] == score["basis"]
    assert isinstance(invocation["properties"]["limitations"], list)


def test_the_document_names_its_version_and_its_schema():
    document = build_sarif(ALL_FINDINGS, engine_version=AUDIT_ENGINE_VERSION,
                           project_name="acme/app")
    assert document["version"] == SARIF_VERSION == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    assert document["runs"][0]["tool"]["driver"]["version"] == AUDIT_ENGINE_VERSION
    assert document["runs"][0]["properties"] == {"project": "acme/app"}


def test_render_sarif_is_json_text_of_the_same_document():
    text = render_sarif(ALL_FINDINGS, engine_version=AUDIT_ENGINE_VERSION)
    assert json.loads(text) == build_sarif(ALL_FINDINGS,
                                           engine_version=AUDIT_ENGINE_VERSION)


def test_non_ascii_finding_text_survives_rendering():
    """Russian findings are the norm for this product's users, and a document
    full of \\u escapes is technically valid and unreadable to them."""
    russian = {**SECRET, "title": "\u0421\u0435\u043a\u0440\u0435\u0442 \u0432 \u043a\u043e\u0434\u0435"}
    text = render_sarif([russian], engine_version=AUDIT_ENGINE_VERSION)
    assert "\u0421\u0435\u043a\u0440\u0435\u0442 \u0432 \u043a\u043e\u0434\u0435" in text
    assert "\\u0421" not in text
