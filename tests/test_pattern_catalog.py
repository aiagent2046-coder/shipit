"""The bundled pattern catalog must remain tied to executable scanner evidence."""

import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import zipfile

import pytest

from app.capabilities import CAPABILITIES
from app.scan import pattern_catalog
from app.scan.outbound_url import scan_outbound_url
from app.scan.sql_injection import scan_sql_injection
from app.scan.unsafe_deserialization import scan_unsafe_deserialization


ROOT = Path(__file__).resolve().parents[1]
SCANNERS = {
    "sql_injection": scan_sql_injection,
    "unsafe_deserialization": scan_unsafe_deserialization,
    "outbound_url": scan_outbound_url,
}


def raw_catalog():
    manifest = pattern_catalog.catalog_manifest()
    manifest.pop("catalog_sha256")
    return manifest


def fixture_archive(directory: Path):
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        for path in sorted(directory.rglob("*.fixture")):
            archive.writestr(path.relative_to(directory).as_posix().removesuffix(".fixture"), path.read_bytes())
    content.seek(0)
    return content


def test_catalog_identity_covers_contents_and_both_version_levels(monkeypatch):
    manifest = pattern_catalog.catalog_manifest()
    digest = manifest.pop("catalog_sha256")
    encoded = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    assert hashlib.sha256(encoded.encode()).hexdigest() == digest
    for change in ("catalog_version", "revision", "guidance"):
        changed = copy.deepcopy(manifest)
        if change == "catalog_version":
            changed["catalog_version"] += ".next"
        elif change == "revision":
            changed["cards"][0]["revision"] += 1
        else:
            changed["cards"][0]["recipe"]["steps"][0] += " Additional reviewed guidance."
        monkeypatch.setattr(pattern_catalog, "_CATALOG", changed)
        assert pattern_catalog.catalog_manifest()["catalog_sha256"] != digest


def test_returned_data_cannot_change_future_catalogs_or_lookups():
    original = pattern_catalog.catalog_manifest()
    manifest = pattern_catalog.catalog_manifest()
    manifest["cards"][0]["recipe"]["automatic_apply"] = True
    selected = pattern_catalog.get_card("python-sql-string-assembly")
    selected["recipe"]["preconditions"].clear()
    pattern_catalog.cards()[0]["detection"]["rule_ids"].clear()
    pattern_catalog.cards_for("sql_injection", "sql-injection-string-built-query")[0]["revision"] += 1
    assert pattern_catalog.catalog_manifest() == original


def test_rule_id_alone_cannot_select_a_driver_specific_recipe():
    rule = "sql-injection-string-built-query"
    python_card, = pattern_catalog.cards_for("sql_injection", rule)
    assert python_card["recipe"]["id"] == "sql-value-parameterization-python-psycopg3"
    assert pattern_catalog.cards_for("sql_injection_js", rule) == ()
    assert pattern_catalog.cards_for("missing_check", rule) == ()
    assert pattern_catalog.cards_for("sql_injection", "missing_rule") == ()
    with pytest.raises(KeyError):
        pattern_catalog.get_card("missing-card")


@pytest.mark.parametrize("card", pattern_catalog.cards(), ids=lambda card: card["id"])
def test_card_examples_actually_exercise_the_declared_check(card):
    check = card["detection"]["check"]
    capability = next(item for item in CAPABILITIES if item.check == check)
    rule_ids = set(card["detection"]["rule_ids"])
    assert rule_ids <= set(capability.rule_ids)
    for polarity in ("positive", "negative"):
        for reference in card["verification"][polarity + "_refs"]:
            directory = ROOT / reference
            expected = json.loads((directory / "expected.json").read_text())
            if polarity == "positive":
                assert rule_ids <= {item["rule_id"] for item in expected["expect"]}
            else:
                assert rule_ids <= set(expected["forbid"])
            coverage = {}
            findings = SCANNERS[check](fixture_archive(directory), coverage=coverage)
            emitted = {finding.rule_id for finding in findings}
            assert coverage["eligible_files"] > 0 and coverage["partial"] is False
            assert (rule_ids <= emitted) if polarity == "positive" else not (rule_ids & emitted)


def test_verification_references_exist_and_test_names_are_collectable():
    for card in pattern_catalog.cards():
        verification = card["verification"]
        references = (verification["positive_refs"] + verification["negative_refs"]
                      + verification["unknown_refs"] + verification["mutation"]["refs"])
        for reference in references:
            relative, _, test_name = reference.partition("::")
            path = (ROOT / relative).resolve()
            assert path.is_relative_to(ROOT) and path.exists(), reference
            if test_name:
                tree = ast.parse(path.read_text())
                assert any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                           and node.name == test_name and node.name.startswith("test_")
                           for node in tree.body), reference
            elif path.is_dir():
                assert (path / "expected.json").is_file() and list(path.rglob("*.fixture")), reference


@pytest.mark.parametrize("mutation", [
    "unknown_schema", "duplicate_id", "unknown_check", "wrong_rule", "javascript_driver",
    "automatic_apply", "runtime_verified", "missing_driver", "missing_evidence_description",
    "unsupported_claim", "unknown_field",
])
def test_broken_links_or_stronger_claims_are_rejected_before_publication(monkeypatch, mutation):
    catalog = raw_catalog()
    card = catalog["cards"][0]
    if mutation == "unknown_schema":
        catalog["schema_version"] = 2
    elif mutation == "duplicate_id":
        catalog["cards"].append(copy.deepcopy(card))
    elif mutation == "unknown_check":
        card["detection"]["check"] = "unimplemented_scanner"
    elif mutation == "wrong_rule":
        card["detection"]["rule_ids"] = ["unsafe-deserialization"]
    elif mutation == "javascript_driver":
        card["detection"]["check"] = "sql_injection_js"
    elif mutation == "automatic_apply":
        card["recipe"]["automatic_apply"] = True
    elif mutation == "runtime_verified":
        card["verification"]["runtime_status"] = "verified"
    elif mutation == "missing_driver":
        card["recipe"]["preconditions"].remove("psycopg3_cursor_provenance")
    elif mutation == "missing_evidence_description":
        card["applicability"]["evidence_descriptions"].pop("attacker_control")
    elif mutation == "unsupported_claim":
        card["weaknesses"][0]["relationship"] = "confirmed_vulnerability"
    else:
        card["recipe"]["executor"] = "app.fixpack.static_security_fixes.apply_sqli_fixes"
    monkeypatch.setattr(pattern_catalog, "_CATALOG", catalog)
    with pytest.raises(ValueError, match="Invalid bundled pattern catalog"):
        pattern_catalog.catalog_manifest()
