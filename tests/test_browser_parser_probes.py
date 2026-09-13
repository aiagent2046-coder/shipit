"""Golden Unicode boundaries for the shared native/Wasm parser probes."""

import json
from pathlib import Path
import runpy

import pytest


@pytest.fixture(scope="module")
def probes():
    source = Path(__file__).resolve().parents[1] / "browser/scripts/parser_probes.py"
    return runpy.run_path(str(source))["probe_parsers"]()


@pytest.mark.parametrize(
    "language,span,start,end",
    [
        ("typescript", [70, 78], [2, 21], [2, 29]),
        ("tsx", [100, 108], [2, 59], [2, 67]),
        ("javascript", [68, 76], [2, 27], [2, 35]),
    ],
)
def test_interpolation_after_unicode_has_utf8_byte_positions(probes, language, span, start, end):
    nodes = probes["tree_sitter"][language]["nodes"]
    interpolation, = [node for node in nodes if node["type"] == "template_substitution"]
    assert interpolation["span"] == span
    assert interpolation["start_point"] == start
    assert interpolation["end_point"] == end
    assert bytes.fromhex(interpolation["text_hex"]).decode() == "${café}"
    call, = [node for node in nodes if node["type"] == "call_expression"]
    assert [field["field"] for field in call["fields"]] == ["function", "arguments"]


def test_sql_scanner_inclusive_characters_differ_from_utf8_bytes(probes):
    tokens = probes["pglast"]["tokens"]
    literal, = [token for token in tokens if token["name"] == "SCONST"]
    assert (literal["start"], literal["end"], literal["byte_span"]) == (19, 28, [24, 39])
    assert literal["text"] == "'élan Ж 😀'"
    second_select = [token for token in tokens if token["name"] == "SELECT"][1]
    assert (second_select["start"], second_select["end"], second_select["byte_span"]) == (64, 69, [79, 85])
    assert probes["pglast"]["invalid_sql"]["error"] == {
        "class": "ParseError", "args": ['syntax error at or near ";"', 11],
    }


def test_probe_is_json_and_exposes_real_ast_classes(probes):
    assert json.loads(json.dumps(probes, allow_nan=False)) == probes
    first, second = probes["pglast"]["ast"]
    assert first["@"] == second["@"] == "RawStmt"
    assert first["stmt"]["targetList"][0]["val"]["val"] == {"@": "String", "sval": "élan Ж 😀"}
    assert second["stmt"]["whereClause"]["@"] == "A_Expr"
    assert second["stmt"]["fromClause"][0]["relname"] == "events"
