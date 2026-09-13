"""Source-bound pagination grouping, with no repository execution or API calls."""
from collections import Counter
from copy import deepcopy
from dataclasses import asdict, replace
import io
import json
import zipfile

import pytest

from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.issue_identity import SourceIssueResolver
from app.scan.query_read_identity import valid_query_read_identity
from app.scan.scoring import ScoredFinding, compute_scores

SOURCE = """async function GET(req) {
  const afterTs = req.after;
  let query = db.from('messages')
    .select('*').eq('match_id', matchId)
    .order('created_at', { ascending: true });
  if (afterTs) query = query.gt('created_at', afterTs);
  return await query;
}
"""
TITLES = ("GET /api/messages fetches all messages for a match with no LIMIT",
          "Messages GET endpoint fetches all messages for a match with no pagination limit")


def _resolver(source=SOURCE):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr("route.ts", source)
    archive.seek(0)
    return SourceIssueResolver(archive)


def _raw(title=TITLES[0], **kwargs):
    return {"file": "route.ts", "line_start": 3, "line_end": 7, "title": title,
            "observation": "The query selects all messages for a match_id with no limit.",
            "explanation": "A large conversation produces a large initial response payload.",
            "fix_hint": "Add a limit and explicit pagination for older messages.",
            "required_conditions": ["A match accumulates many messages", "A user opens the chat"],
            "premises": [{"kind": "query_limit_unbounded", "target": "messages",
                          "line_start": 3, "line_end": 7}], **kwargs}


def _finding(raw=None, *, response=3, source=SOURCE, identity="resolve"):
    raw = raw or _raw()
    if identity == "resolve":
        identity = _resolver(source).identity(raw)
    return ScoredFinding(
        rule_id="llm-money", title=raw["title"], severity="low", confidence=0.75,
        category="Money & Data", file="route.ts", line=raw["line_start"],
        explanation=raw["explanation"], fix_hint=raw["fix_hint"], source="llm",
        verification_method="model_review", verification_status="unverified",
        claim_evidence={"version": 1, "source_issue_identity": identity,
                        "source_check": {"kind": "quote_match", "line_start": raw["line_start"],
                                         "line_end": raw["line_end"]},
                        "producer": {"model": "synthetic-model", "rubric": "money", "response": response},
                        "observation": raw["observation"], "required_conditions": raw["required_conditions"],
                        "conditions_status": "not_checked", "consequence_status": "not_checked",
                        "syntax_check": {"kind": "unsupported", "result": "not_checked"},
                        "premise_checks": [{**p, "result": "not_checked"} for p in raw["premises"]],
                        "source_assessments": []})


def _fingerprints(rows):
    return Counter(json.dumps(row, sort_keys=True) for row in rows)


def test_two_pass_paraphrases_group_only_common_scope_preserving_conditions_and_score():
    first = _finding()
    second = _finding(_raw(TITLES[1],
        observation="The query returns all messages. The after filter helps polling but not initial loading.",
        explanation="The messages table has no retention policy, so old conversations keep growing.",
        required_conditions=["A match accumulates many messages", "Users frequently reload the chat"],
        fix_hint="Add a limit of 100 to the initial query and pagination for older messages."), response=7)
    assert first.claim_evidence["source_issue_identity"] == second.claim_evidence["source_issue_identity"]
    original = [asdict(first), asdict(second)]
    grouped = dedup_cross_rubric([first, second])
    assert len(grouped) == 1
    assert grouped[0].title == "Query pagination bound requires review"
    assert "separate claims" in grouped[0].explanation
    assert grouped[0].claim_evidence["grouped_claim_scope"]["mechanism"] == "query_read_volume"
    assert _fingerprints(grouped[0].claim_evidence["grouped_originals"]) == _fingerprints(original)
    assert [asdict(first), asdict(second)] == original
    assert compute_scores(grouped) == compute_scores([first])
    assert dedup_cross_rubric(grouped) == grouped
    assert dedup_cross_rubric([*grouped, first, second]) == grouped


def test_scanner_uses_source_operation_not_injected_model_metadata():
    raw = _raw(source_issue_identity={"operation_span": [0, 1]}, claim_scope="owner_check")
    identity = _resolver().identity(raw)
    assert valid_query_read_identity(identity, "route.ts")
    assert identity["operation_span"] != [0, 1]
    assert identity["claim_scope"] == "select_pagination_bound"
    assert "messages" not in json.dumps(identity)


def test_group_keeps_existing_highest_severity_score_without_verifying_damage():
    low = _finding()
    high = replace(_finding(_raw(TITLES[1]), response=7), severity="high", confidence=0.9)
    grouped = dedup_cross_rubric([low, high])
    assert len(grouped) == 1
    assert compute_scores(grouped) == compute_scores([high])
    assert grouped[0].verification_status == "unverified"
    assert grouped[0].claim_evidence["consequence_status"] == "not_checked"
    assert {f["severity"] for f in grouped[0].claim_evidence["grouped_originals"]} == {"low", "high"}


@pytest.mark.parametrize("other", [
    "  const other = db.from('messages').select('*');",
    "  const count = db.from('messages').select('*', {count: 'exact', head: true});",
])
def test_nearby_read_and_count_queries_cannot_be_collapsed(other):
    source = SOURCE.replace("  return await query;", other + "\n  return await query;")
    a = _finding(_raw(line_end=5, premises=[]), source=source)
    b = _finding(_raw(TITLES[1], line_start=7, line_end=7, premises=[]), source=source)
    assert a.claim_evidence["source_issue_identity"]
    assert a.claim_evidence["source_issue_identity"] != b.claim_evidence["source_issue_identity"]
    assert len(dedup_cross_rubric([a, b])) == 2


@pytest.mark.parametrize("field,value", [
    ("title", TITLES[0] + " and lacks ownership checks"),
    ("title", "Messages query fetches all messages with no LIMIT and lacks ownership checks"),
    ("observation", "The query has no owner filter, so other users' messages are accessible."),
    ("explanation", "The entire history is forwarded to an LLM, inflating prompt tokens."),
    ("explanation", "A race condition in the nearby count query allows duplicate paid calls."),
    ("fix_hint", "Add pagination and authentication."),
    ("required_conditions", ["Another user's authentication token is available"]),
    ("observation", "The query already has a limit."),
    ("explanation", "The query is not unbounded."),
    ("observation", {"query": "unlimited"}),
    ("required_conditions", {}),
    ("premises", {}),
    ("explanation", " " * 16001 + "Another claim"),
    ("premises", [{"kind": "ownership_guard_absent", "target": "messages", "line_start": 3, "line_end": 7}]),
])
def test_distinct_and_malformed_claims_cannot_select_common_read_volume_scope(field, value):
    raw = _raw(**{field: value})
    assert _resolver().identity(raw) is None
    if field not in {"premises", "observation"} or not isinstance(value, dict):
        assert len(dedup_cross_rubric([_finding(), _finding(raw, identity=None)])) == 2


@pytest.mark.parametrize("suffix", [
    ".limit(100)", ".range(0, 99)", ".unknownTransform()", ".select('*', {count: 'exact'})",
])
def test_unsupported_chains_have_no_identity(suffix):
    source = SOURCE.replace(".order('created_at', { ascending: true })", suffix)
    assert _resolver(source).identity(_raw()) is None


def test_ambiguous_citation_and_invalid_ast_fail_closed():
    source = SOURCE.replace(
        "  return await query;", "  const other = db.from('messages').select('*');\n  return await query;")
    assert _resolver(source).identity(_raw(line_end=8, premises=[])) is None
    assert _resolver("async function broken( {").identity(_raw()) is None


@pytest.mark.parametrize("query", ["db.from(table).select('*')", "db.from('other').select('*')",
                                     "db.from('messages').select(columns)"])
def test_dynamic_or_different_table_and_column_selection_abstain(query):
    source = "async function GET() {\n  return " + query + ";\n}\n"
    assert _resolver(source).identity(_raw(line_start=2, line_end=2, premises=[])) is None


@pytest.mark.parametrize("field,value", [
    ("mechanism", "query_read_volume_other"), ("method", "model_claim"), ("version", True),
    ("claim_scope", "ownership"), ("table_sha256", "not-a-digest"),
    ("operation_span", [0, 999999]), ("function_span", [0, 0]), ("operation_line_start", True),
    ("file", "../route.ts"), ("source_sha256", "invalid"),
])
def test_malformed_identity_cannot_enable_grouping(field, value):
    evidence = deepcopy(_finding().claim_evidence)
    evidence["source_issue_identity"][field] = value
    assert not valid_query_read_identity(evidence["source_issue_identity"], "route.ts")
    a = replace(_finding(), claim_evidence=evidence)
    b = replace(_finding(_raw(TITLES[1])), claim_evidence=deepcopy(evidence))
    assert len(dedup_cross_rubric([a, b])) == 2


@pytest.mark.parametrize("key,value", [
    ("source_sha256", "f" * 64), ("table_sha256", "f" * 64),
    ("operation_span", [40, 50]), ("operation_line_start", 4),
])
def test_changed_source_or_operation_identity_stays_separate(key, value):
    a, b = _finding(), _finding(_raw(TITLES[1]))
    evidence = deepcopy(b.claim_evidence)
    evidence["source_issue_identity"][key] = value
    assert len(dedup_cross_rubric([a, replace(b, claim_evidence=evidence)])) == 2


@pytest.mark.parametrize("field,value", [
    ("conditions_status", "observed"), ("consequence_status", "contradicted"),
    ("source_assessments", [{"kind": "query_read_bound", "result": "contradicted", "whole_finding": False}]),
    ("syntax_check", {"kind": "query_limit_unbounded", "result": "contradicted"}),
    ("premise_checks", [{"kind": "ownership_guard_absent", "target": "messages", "result": "not_checked"}]),
    ("producer", {"model": "synthetic-model", "rubric": "money", "response": 0}),
    ("source_check", {"kind": "quote_match", "line_start": 3, "line_end": 7, "source_sha256": "f" * 64}),
])
def test_different_dispositions_and_inconsistent_evidence_remain_separate(field, value):
    a, b = _finding(), _finding(_raw(TITLES[1]))
    evidence = {**b.claim_evidence, field: value}
    assert len(dedup_cross_rubric([a, replace(b, claim_evidence=evidence)])) == 2


@pytest.mark.parametrize("field,value", [
    ("verification_status", "observed"), ("verification_method", "source_analysis"),
    ("source", "static"), ("category", "Auth"), ("origin_category", "Security"),
])
def test_different_execution_dispositions_remain_separate(field, value):
    assert len(dedup_cross_rubric([_finding(), replace(_finding(_raw(TITLES[1])), **{field: value})])) == 2


def test_parser_unavailable_and_budget_exhaustion_abstain(monkeypatch):
    import app.scan.issue_identity as module
    for field in ("remaining_nodes", "remaining"):
        resolver = _resolver()
        setattr(resolver, field, 0)
        assert resolver.identity(_raw()) is None
    resolver = _resolver()
    resolver.checks = module.MAX_CHECKS
    assert resolver.identity(_raw()) is None
    def missing_parser(*args, **kwargs):
        raise ModuleNotFoundError("synthetic parser unavailable")
    monkeypatch.setattr(module, "Parser", missing_parser)
    assert _resolver().identity(_raw()) is None
    assert len(dedup_cross_rubric([_finding(identity=None), _finding(_raw(TITLES[1]), identity=None)])) == 2


@pytest.mark.parametrize("field,value", [
    ("line_start", None), ("line_start", "3"), ("line_start", True), ("line_end", []),
    ("required_conditions", [None]), ("required_conditions", [""]),
])
def test_malformed_coordinates_and_conditions_do_not_raise_or_select_identity(field, value):
    assert _resolver().identity(_raw(**{field: value})) is None
