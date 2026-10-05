"""A saved table/binding mismatch must group only after source proof, without LLM calls."""
from collections import Counter
from copy import deepcopy
from dataclasses import asdict, replace
from hashlib import sha256
import io
import json
from pathlib import Path
import zipfile

import pytest

from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.issue_identity import SourceIssueResolver
from app.scan.query_read_identity import valid_query_read_identity
from app.scan.scoring import ScoredFinding


SOURCE = """async function GET(req) {
  const afterTs = req.after;
  let query = db.from('messages')
    .select('*').eq('match_id', matchId)
    .order('created_at', { ascending: true });
  if (afterTs) query = query.gt('created_at', afterTs);
  return await query;
}
"""
TITLE = "GET messages endpoint fetches all messages for a match with no pagination limit"


def _resolver(source=SOURCE, path="route.ts"):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr(path, source)
    archive.seek(0)
    return SourceIssueResolver(archive)


def _raw(target="query", source=SOURCE):
    end = len(source.splitlines()) - 1
    return {
        "file": "route.ts", "title": TITLE, "line_start": 3, "line_end": end,
        "observation": "The query selects all messages without an explicit row limit.",
        "explanation": "Long conversations can increase the initial response payload.",
        "fix_hint": "Add a row limit and cursor pagination.",
        "required_conditions": ["A match accumulates many messages"],
        "premises": [{"kind": "query_limit_unbounded", "target": target,
                      "line_start": 3, "line_end": end}],
    }


def _finding(target="query", *, source=SOURCE, response=3):
    raw = _raw(target, source)
    return ScoredFinding(
        rule_id="llm-money", title=raw["title"], severity="low", confidence=0.7,
        category="Money & Data", source="llm", file=raw["file"], line=3,
        explanation=raw["explanation"], fix_hint=raw["fix_hint"],
        verification_method="model_review", verification_status="unverified",
        claim_evidence={
            "version": 1, "source_issue_identity": _resolver(source).identity(raw),
            "producer": {"model": "fixture-model", "rubric": "money", "response": response},
            "source_check": {"kind": "quote_match", "line_start": 3, "line_end": raw["line_end"]},
            "observation": raw["observation"], "required_conditions": raw["required_conditions"],
            "premise_checks": [{**raw["premises"][0], "result": "not_checked"}],
            "conditions_status": "not_checked", "consequence_status": "not_checked",
            "syntax_check": {"kind": "unsupported", "result": "not_checked"},
            "source_assessments": [],
        },
    )


def _fingerprints(rows):
    return Counter(json.dumps(row, sort_keys=True) for row in rows)


def test_saved_pagination_pair_resolves_binding_and_preserves_every_original_claim():
    fixture = json.loads((Path(__file__).parent / "fixtures/query_binding_d8ae8860.json").read_text())
    resolver = _resolver(fixture["source"], fixture["source_file"])
    findings = []
    for saved in fixture["findings"]:
        row = deepcopy(saved)
        evidence = row["claim_evidence"]
        check = evidence["source_check"]
        raw = {
            **row, "line_start": check["line_start"], "line_end": check["line_end"],
            "observation": evidence["observation"],
            "required_conditions": evidence["required_conditions"],
            "premises": [{key: premise[key] for key in ("kind", "target", "line_start", "line_end")}
                         for premise in evidence["premise_checks"]],
        }
        evidence["source_issue_identity"] = resolver.identity(raw)
        findings.append(ScoredFinding(**row))

    left, right = [item.claim_evidence["source_issue_identity"] for item in findings]
    assert left is not None and left == right
    assert left["version"] == 2
    assert left["binding"]["name_sha256"] == sha256(b"query").hexdigest()
    assert valid_query_read_identity(left, fixture["source_file"])
    encoded = fixture["source"].encode()
    begin, end = left["binding"]["span"]
    assert encoded[begin:end] == b"query"

    originals = [asdict(item) for item in findings]
    grouped = dedup_cross_rubric(findings)
    assert len(grouped) == 1
    assert grouped[0].title == "Query pagination bound requires review"
    assert grouped[0].verification_status == "unverified"
    assert _fingerprints(grouped[0].claim_evidence["grouped_originals"]) == _fingerprints(originals)
    assert {row["claim_evidence"]["premise_checks"][0]["target"]
            for row in grouped[0].claim_evidence["grouped_originals"]} == {"messages", "query"}
    assert [asdict(item) for item in findings] == originals
    assert dedup_cross_rubric(grouped) == grouped
    assert dedup_cross_rubric([*grouped, *findings]) == grouped
    assert _fingerprints(dedup_cross_rubric(list(reversed(findings)))[0]
                         .claim_evidence["grouped_originals"]) == _fingerprints(originals)


def test_binding_identity_does_not_depend_on_model_selector_name():
    table, binding = _finding("messages"), _finding("query", response=7)
    assert table.claim_evidence["source_issue_identity"] == binding.claim_evidence["source_issue_identity"]
    assert table.claim_evidence["source_issue_identity"]["version"] == 2
    assert len(dedup_cross_rubric([table, binding])) == 1


@pytest.mark.parametrize("statement", [
    "query = db.from('other').select('*');",
    "query = db.from('messages').select('*');",
    "query = other;",
    "query += other;",
    "query++;",
    "({query} = other);",
    "[query] = other;",
    "for (query of queries) {}",
    "{ let query = other; }",
    "try {} catch (query) {}",
    "const callback = (query) => query;",
    "const callback = () => query;",
    "const callback = () => { query = other; };",
    "query.gt = replacement;",
    "const alias = query;",
    "consume(query);",
    "query = query.unknownTransform();",
    "query = query['gt']('id', 1);",
    "query = query?.gt('id', 1);",
    "query = query.gt?.('id', 1);",
    "query = query.gt('id', consume(query));",
    "query = query.limit(100);",
    "query = query.range(0, 99);",
    "eval(expression);",
    r"qu\u0065ry = other;",
    r"{ let qu\u0065ry = other; }",
    r"const callback = () => qu\u0065ry;",
])
def test_ambiguous_or_escaped_binding_cannot_resolve_alias_premise(statement):
    source = SOURCE.replace("  return await query;", f"  {statement}\n  return await query;")
    assert _resolver(source).identity(_raw("query", source)) is None
    assert len(dedup_cross_rubric([_finding("messages", source=source),
                                 _finding("query", source=source, response=7)])) == 2


@pytest.mark.parametrize("source", [
    SOURCE.replace(".from('messages')", ".from('other')"),
    SOURCE.replace(".select('*')", ".select('*').limit(100)"),
    SOURCE.replace(".select('*')", ".select('*', {count: 'exact', head: true})"),
    SOURCE.replace("  return await query;", "  await query;\n  return await query;"),
    SOURCE.replace("  return await query;", "  return query;"),
])
def test_binding_is_not_proof_for_other_table_limited_count_or_ambiguous_use(source):
    assert _resolver(source).identity(_raw("query", source)) is None


def test_alias_premise_cannot_select_an_uncited_operation_or_hide_another_claim():
    raw = _raw()
    raw["premises"][0].update(line_start=7, line_end=7)
    assert _resolver().identity(raw) is None
    raw = _raw()
    raw["premises"].append({"kind": "ownership_guard_absent", "target": "messages",
                            "line_start": 3, "line_end": 5})
    assert _resolver().identity(raw) is None
    assert _resolver().identity(_raw("unrelated")) is None


@pytest.mark.parametrize("coordinates", [
    {"line_start": 2, "line_end": 7},
    {"line_start": 3, "line_end": 8},
    {"anchor_line_start": 2, "anchor_line_end": 7},
    {"anchor_line_start": 3, "anchor_line_end": 8},
    {"anchor_line_start": 7, "anchor_line_end": 7},
    {"anchor_line_start": 3},
])
def test_saved_alias_premise_must_stay_within_quote_and_operation(coordinates):
    table, binding = _finding("messages"), _finding("query", response=7)
    evidence = deepcopy(binding.claim_evidence)
    evidence["premise_checks"][0].update(coordinates)
    assert len(dedup_cross_rubric([table, replace(binding, claim_evidence=evidence)])) == 2


def test_saved_table_premise_citing_only_await_cannot_normalize_to_select_alias():
    table, binding = _finding("messages"), _finding("query", response=7)
    evidence = deepcopy(table.claim_evidence)
    evidence["premise_checks"][0].update(line_start=7, line_end=7)
    assert len(dedup_cross_rubric([replace(table, claim_evidence=evidence), binding])) == 2


@pytest.mark.parametrize("field,value", [
    ("source_sha256", "f" * 64),
    ("table_sha256", "f" * 64),
    ("operation_span", [35, 40]),
])
def test_changed_source_table_or_operation_cannot_join_with_original(field, value):
    table, binding = _finding("messages"), _finding("query", response=7)
    evidence = deepcopy(binding.claim_evidence)
    evidence["source_issue_identity"][field] = value
    assert len(dedup_cross_rubric([table, replace(binding, claim_evidence=evidence)])) == 2


@pytest.mark.parametrize("field,value", [
    ("result", "contradicted"), ("result", "observed"),
    ("scope", "other_operation"), ("whole_finding", True),
    ("disposition", "retain_separately"), ("source_entities", ["another_query"]),
    ("narrative_review", "needs_review"),
])
def test_target_projection_preserves_different_scanner_dispositions(field, value):
    table, binding = _finding("messages"), _finding("query", response=7)
    evidence = deepcopy(binding.claim_evidence)
    evidence["premise_checks"][0][field] = value
    assert len(dedup_cross_rubric([table, replace(binding, claim_evidence=evidence)])) == 2


@pytest.mark.parametrize("result", ["contradicted", "observed"])
def test_even_matching_checked_results_do_not_normalize_distinct_targets(result):
    findings = [_finding("messages"), _finding("query", response=7)]
    for finding in findings:
        finding.claim_evidence["premise_checks"][0]["result"] = result
    assert len(dedup_cross_rubric(findings)) == 2


def test_legacy_identity_cannot_attest_a_binding_name():
    findings = [_finding("messages"), _finding("query", response=7)]
    for finding in findings:
        identity = finding.claim_evidence["source_issue_identity"]
        assert identity is not None
        identity.pop("binding")
        identity["version"] = 1
        assert valid_query_read_identity(identity, "route.ts")
    assert len(dedup_cross_rubric(findings)) == 2


def test_unproved_binding_does_not_invalidate_legacy_table_only_identity():
    source = SOURCE.replace("  return await query;", "  consume(query);\n  return await query;")
    identity = _resolver(source).identity(_raw("messages", source))
    assert identity is not None
    assert identity["version"] == 1
    assert "binding" not in identity
    assert valid_query_read_identity(identity, "route.ts")
    assert _resolver(source).identity(_raw("query", source)) is None


@pytest.mark.parametrize("binding", [
    None, {}, {"name_sha256": "bad", "span": [1, 2]},
    {"name_sha256": "f" * 64, "span": [0, 999999]},
    {"name_sha256": "f" * 64, "span": [False, 4]},
    {"name_sha256": "f" * 64, "span": [5, 5]},
    {"name_sha256": "f" * 64, "span": [1, 2], "proof": "model_supplied"},
])
def test_malformed_binding_proof_cannot_relax_comparison(binding):
    findings = [_finding("messages"), _finding("query", response=7)]
    for finding in findings:
        identity = finding.claim_evidence["source_issue_identity"]
        assert identity is not None
        identity["binding"] = deepcopy(binding)
        assert not valid_query_read_identity(identity, "route.ts")
    assert len(dedup_cross_rubric(findings)) == 2
