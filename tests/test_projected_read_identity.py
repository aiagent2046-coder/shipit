"""Minimized, synthetic regression for projected reads followed by a sanitizer."""
from collections import Counter
from copy import deepcopy
from dataclasses import asdict, replace
import json
import io
import zipfile

import pytest

from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.issue_identity import SourceIssueResolver
from app.scan.projected_read_identity import (
    compatible_projected_read_claims, projected_read_claim, projected_read_identity,
    projected_read_related_title, valid_projected_read_identity,
)
from app.scan.scoring import ScoredFinding

SOURCE = """async function POST() {
  const { data: facts } = await db.from('agent_context')
    .select('content').eq('user_id', user.id)
    .order('created_at', {ascending: false});
  const safe = sanitizeFacts(facts ?? []);
  return safe;
}
"""
TITLES = ["Agent chats read all matching saved facts", "Could growing history reads be capped?"]
OBSERVATIONS = [
    "The route selects saved-fact content for the current user and orders the results without specifying a limit.",
    "The `agent_context` query selects content, filters by user, and orders the results; "
    "no limit or pagination is specified in this query.",
]


def resolver(source=SOURCE):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr("route.ts", source)
    archive.seek(0)
    return SourceIssueResolver(archive)


def raw(index=0, **kwargs):
    return {"file": "route.ts", "line_start": 2, "line_end": 5, "title": TITLES[index],
            "observation": OBSERVATIONS[index],
            "explanation": "The query has no query-level limit; the effective API cap is unresolved.",
            "fix_hint": "Verify the effective API cap; retain only facts needed for the prompt.",
            "required_conditions": ["Many saved facts accumulate.", "No API row cap applies."],
            "premises": [{"kind": "query_limit_unbounded", "target": "facts", "line_start": 2, "line_end": 4}],
            **kwargs}


def finding(index=0, **kwargs):
    r = raw(index, **kwargs)
    return ScoredFinding(
        rule_id="llm-money", title=r["title"], severity="low", confidence=0.5, category="Money & Data",
        file="route.ts", line=2, explanation=r["explanation"], fix_hint=r["fix_hint"], source="llm",
        verification_status="unverified", verification_method="model_review",
        claim_evidence={"version": 1, "source_issue_identity": projected_read_identity(r, resolver()),
                        "source_check": {"kind": "quote_match", "line_start": 2, "line_end": 5},
                        "producer": {"model": "synthetic", "rubric": "money", "response": 3 + 4 * index},
                        "observation": r["observation"], "required_conditions": r["required_conditions"],
                        "conditions_status": "not_checked", "consequence_status": "not_checked",
                        "premise_checks": [{**p, "result": "not_checked"} for p in r["premises"]],
                        "context_checks": [{"kind": "imported_collection_return_cap", "result": "observed"}]})


def test_projected_read_identity_is_source_bound_and_does_not_negate_later_sanitizer():
    a, b = finding(0), finding(1, required_conditions=["The history grows and effective API caps do not apply."])
    identity = a.claim_evidence["source_issue_identity"]
    assert identity and identity == b.claim_evidence["source_issue_identity"]
    assert valid_projected_read_identity(identity, "route.ts")
    assert compatible_projected_read_claims(a, b, identity)
    assert identity["claim_scope"] == "projected_select_read_bound"
    assert a.claim_evidence["context_checks"][0]["result"] == "observed"
    assert "agent_context" not in repr(identity)
    altered = projected_read_identity(raw(), resolver(SOURCE.replace("user.id", "other.id")))
    assert altered != identity


@pytest.mark.parametrize("source", [
    SOURCE.replace(".select('content')", ".select('*')"),
    SOURCE.replace(".select('content')", ".select('content', {count: 'exact', head: true})"),
    SOURCE.replace(".select('content')", ".select('content').limit(40)"),
    SOURCE.replace(".select('content')", ".select('content').range(0, 39)"),
    SOURCE.replace(".select('content')", ".select('content').maybeSingle()"),
    SOURCE.replace(".select('content')", ".select(columns)"),
    SOURCE.replace(".select('content')", ".select('content,other')"),
    SOURCE.replace(".select('content')", ".select('content').unknown()"),
    SOURCE.replace(".select('content')", "?.select('content')"),
    SOURCE.replace("data: facts", "data: another"),
    SOURCE.replace("data: facts", "data: facts = []"),
    SOURCE.replace("data: facts", "data: facts, ...rest"),
    SOURCE.replace("const {", "let {"),
    SOURCE.replace("await db", "db"),
    SOURCE.replace(".eq('user_id', user.id)", ".eq(field, user.id)"),
    SOURCE.replace("  const safe",
                   "  const {data: other} = await db.from('agent_context').select('content'); const safe"),
])
def test_unsupported_or_ambiguous_read_does_not_get_identity(source):
    assert projected_read_identity(raw(), resolver(source)) is None


@pytest.mark.parametrize("field,value", [
    ("title", TITLES[0] + " and allows SQL injection"),
    ("observation", OBSERVATIONS[0] + " All facts enter an unbounded prompt."),
    ("explanation", "The prompt has no bound and token bills grow."),
    ("explanation", "The query bypasses RLS."),
    ("explanation", "sanitizeFacts fails to bound the data."),
    ("fix_hint", "Prevent prompt injection."),
    ("required_conditions", ["An attacker bypasses authentication."]),
])
def test_compound_claims_do_not_reuse_database_read_identity(field, value):
    assert projected_read_claim(raw(**{field: value})) is None
    assert projected_read_identity(raw(**{field: value}), resolver()) is None
    assert projected_read_related_title(TITLES[0] + " and SQL injection")


@pytest.mark.parametrize("premises", [[], None,
    [{"kind": "query_limit_unbounded", "target": "other", "line_start": 2, "line_end": 4}],
    [{"kind": "query_limit_unbounded", "target": "facts", "line_start": 5, "line_end": 5}],
    [{"kind": "query_limit_unbounded", "target": "facts", "line_start": 1, "line_end": 4}],
])
def test_unbound_premise_alias_or_coordinates_abstain(premises):
    assert projected_read_identity(raw(premises=premises), resolver()) is None


@pytest.mark.parametrize("field", ["conditions_status", "consequence_status"])
def test_changed_verification_disposition_prevents_grouping(field):
    a, b = finding(), finding(1)
    b.claim_evidence[field] = "observed"
    assert not compatible_projected_read_claims(a, b, a.claim_evidence["source_issue_identity"])


def test_premise_counterevidence_cannot_be_promoted_to_common_pending_claim():
    a, b = finding(), finding(1)
    b.claim_evidence["premise_checks"][0]["result"] = "contradicted"
    assert not compatible_projected_read_claims(a, b, a.claim_evidence["source_issue_identity"])


@pytest.mark.parametrize("field,value", [("version", True), ("file", "../route.ts"),
    ("method", "model_claim"), ("claim_scope", "prompt_unbounded"), ("source_sha256", "fake")])
def test_malformed_saved_identity_rejected(field, value):
    identity = deepcopy(finding().claim_evidence["source_issue_identity"])
    identity[field] = value
    assert not valid_projected_read_identity(identity, "route.ts")


def test_quote_for_another_statement_does_not_select_query():
    assert projected_read_identity(raw(line_start=5, line_end=5), resolver()) is None


def test_budgets_and_parse_failures_abstain():
    limited = resolver()
    limited.remaining_nodes = 0
    assert projected_read_identity(raw(), limited) is None
    assert projected_read_identity(raw(), resolver("broken {")) is None


@pytest.mark.parametrize("anchors", [
    {"anchor_line_start": 5, "anchor_line_end": 5},
    {"anchor_line_start": 2},
    {"anchor_line_start": True, "anchor_line_end": 4},
])
def test_original_premise_anchors_cannot_select_another_statement(anchors):
    r = raw()
    r["premises"][0].update(anchors)
    assert projected_read_identity(r, resolver()) is None


@pytest.mark.parametrize("statement", [
    "facts = other;", "facts += other;", "facts++;", "const facts = other;",
    "function nested(facts) { return facts; }", "({data: facts} = other);",
    "for (facts of other) {}", "eval('changeBinding()');",
    r"fac\u0074s = other;",
])
def test_reassignment_shadowing_and_escaped_binding_abstain(statement):
    source = SOURCE.replace("  return safe;", f"  {statement}\n  return safe;")
    assert projected_read_identity(raw(), resolver(source)) is None


def test_shared_resolver_and_dedup_preserve_different_conditions_severity_and_sanitizer_context():
    a = finding()
    b = replace(finding(1, required_conditions=["The saved facts grow beyond an effective cap."]), severity="medium")
    assert resolver().identity(raw()) == a.claim_evidence["source_issue_identity"]
    before = [asdict(a), asdict(b)]
    grouped = dedup_cross_rubric([a, b])
    assert len(grouped) == 1
    assert grouped[0].claim_evidence["grouped_claim_scope"]["mechanism"] == "projected_query_read_volume"
    originals = grouped[0].claim_evidence["grouped_originals"]
    assert Counter(json.dumps(x, sort_keys=True) for x in originals) == Counter(
        json.dumps(x, sort_keys=True) for x in before)
    assert [asdict(a), asdict(b)] == before
    assert grouped[0].severity == "medium"
    assert grouped[0].verification_status == "unverified"
    assert all(x["claim_evidence"]["context_checks"][0]["result"] == "observed" for x in originals)
    assert dedup_cross_rubric(grouped) == grouped
    assert dedup_cross_rubric([*grouped, a, b]) == grouped


@pytest.mark.parametrize("field", ["mechanism", "claim_scope"])
def test_forged_identity_marker_cannot_fall_back_to_generic_grouping(field):
    a, b = finding(), finding(1)
    for row in (a, b):
        row.claim_evidence["source_issue_identity"][field] = "unknown"
    assert len(dedup_cross_rubric([a, b])) == 2
