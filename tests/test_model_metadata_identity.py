"""Synthetic model metadata claims; no private source, models or API calls."""
from collections import Counter
from copy import deepcopy
from dataclasses import asdict, replace
import io
import json
import zipfile

import pytest

from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.claim_evidence import model_claim_evidence
from app.scan.issue_identity import SourceIssueResolver
from app.scan.model_metadata_identity import valid_model_metadata_identity
from app.scan.scoring import ScoredFinding, compute_scores


SOURCE = """async function version() {
  const response = await fetch('https://provider.invalid/models/example');
  return response.json();
}
"""
REPEAT = "Model version fetched on every embedding computation"
PAID = "Model version lookup makes a paid API call on every recompute"
PIN = "Model version fetched dynamically without pinning"


def _resolver(source=SOURCE):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr("route.ts", source)
    archive.seek(0)
    return SourceIssueResolver(archive)


def _raw(title=REPEAT, **kwargs):
    return {"file": "route.ts", "line_start": 2, "line_end": 3,
            "title": title, "explanation": "", "observation": "", "fix_hint": "",
            "required_conditions": [], **kwargs}


def _finding(raw=None, *, response=1, rubric="money", identity="resolve"):
    raw = raw or _raw()
    if identity == "resolve":
        identity = _resolver().identity(raw)
    return ScoredFinding(
        rule_id=f"llm-{rubric}", title=raw["title"], severity="medium", confidence=0.8,
        category="Money & Data" if rubric == "money" else "Security", file=raw["file"],
        line=raw["line_start"], explanation=raw["explanation"], fix_hint=raw["fix_hint"],
        source="llm", verification_method="model_review", verification_status="unverified",
        claim_evidence={"version": 1, "source_issue_identity": identity,
                        "producer": {"model": "synthetic-model", "rubric": rubric, "response": response},
                        "source_check": {"kind": "quote_match", "line_start": 2, "line_end": 3},
                        "observation": raw["observation"], "required_conditions": raw["required_conditions"],
                        "conditions_status": "not_checked", "consequence_status": "not_checked",
                        "syntax_check": {"kind": "unsupported", "result": "not_checked"},
                        "premise_checks": [], "context_checks": []})


def _legacy():
    identity = _resolver().identity(_raw())
    identity["version"] = 1
    del identity["claim_scope"], identity["claim_qualifiers"]
    return identity


def _scenario(*, legacy=False, freeform=False):
    pin = _raw(PIN, observation="The model version is not pinned.",
               fix_hint="Pin the model version ID in configuration.",
               required_conditions=["The model owner publishes a new version"])
    cost = _raw(PAID, observation="The model version lookup is not cached.",
                fix_hint="Cache the model version with a TTL.",
                required_conditions=["The provider charges for model metadata GET requests"])
    if freeform:
        pin["title"] += " or signature verification"
        pin["explanation"] = "An upstream revision could change the vector format."
        cost["title"] = "Model-version lookup repeats on every embedding, adding a paid metadata round-trip"
        cost["observation"] = "The helper reloads the version during every retry instead of reusing a TTL cache."
        cost["required_conditions"].append("Extra latency may trigger another retry")
    identity = _legacy() if legacy else "resolve"
    return [_finding(pin, rubric="security", response=2, identity=identity),
            _finding(cost, response=3, identity=identity), _finding(cost, response=7, identity=identity)]


def _fingerprints(rows):
    return Counter(json.dumps(row, sort_keys=True) for row in rows)


def _leaves(rows):
    return [leaf for row in rows for leaf in (row.claim_evidence.get("grouped_originals") or [asdict(row)])]


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("freeform", [False, True])
def test_one_operation_three_originals_become_two_groups_without_losing_claims(legacy, freeform):
    originals = _scenario(legacy=legacy, freeform=freeform)
    before = [asdict(row) for row in originals]
    grouped = dedup_cross_rubric(originals)
    assert len(grouped) == 2
    assert grouped[0] == originals[0]
    assert grouped[1].title == originals[1].title
    assert [row["claim_evidence"]["producer"]["response"]
            for row in grouped[1].claim_evidence["grouped_originals"]] == [3, 7]
    assert _fingerprints(_leaves(grouped)) == _fingerprints(before)
    assert [asdict(row) for row in originals] == before
    assert compute_scores(grouped) == compute_scores(originals[:2])
    assert dedup_cross_rubric(grouped) == grouped


def test_saved_mixed_v1_group_splits_on_replay_and_keeps_overlapping_history_once():
    originals = _scenario(legacy=True, freeform=True)
    evidence = {**originals[1].claim_evidence, "grouped_originals": [asdict(row) for row in originals]}
    saved = replace(originals[1], explanation="An old mixed-group explanation.", claim_evidence=evidence)
    for rows in ([saved], [saved, *originals], [*originals, saved], [saved, saved]):
        grouped = dedup_cross_rubric(rows)
        assert len(grouped) == 2
        assert _fingerprints(_leaves(grouped)) == _fingerprints([asdict(row) for row in originals])
        assert dedup_cross_rubric(grouped) == grouped


def test_version_and_repetition_claims_have_distinct_scopes_for_the_same_operation():
    resolver = _resolver()
    version, repeat = [resolver.identity(_raw(title)) for title in (PIN, REPEAT)]
    assert version["version"] == repeat["version"] == 2
    assert version["claim_scope"] == "version_selection"
    assert repeat["claim_scope"] == "repeated_request"
    for key in ("source_sha256", "file", "function_span", "operation_span"):
        assert version[key] == repeat[key]
    assert "https://" not in json.dumps([version, repeat])
    assert len(dedup_cross_rubric([_finding(_raw(PIN)), _finding(_raw(REPEAT))])) == 2


@pytest.mark.parametrize("titles,scope,conditions", [
    ((REPEAT, "Model version lookup is called on every recompute"), "repeated_request", []),
    ((PIN, "Model version is not pinned"), "version_selection", ["The upstream model version changes"]),
    (("Model version lookup is not cached", "Model version is fetched without caching"),
     "repeated_request", ["The provider charges for model metadata GET requests"]),
])
def test_supported_title_paraphrases_merge_with_identical_compatible_conditions(titles, scope, conditions):
    rows = [_finding(_raw(title, required_conditions=conditions), response=index + 1)
            for index, title in enumerate(titles)]
    assert all(row.claim_evidence["source_issue_identity"]["claim_scope"] == scope for row in rows)
    grouped = dedup_cross_rubric(rows)
    assert len(grouped) == 1
    assert _fingerprints(_leaves(grouped)) == _fingerprints([asdict(row) for row in rows])
    assert all(row["claim_evidence"]["conditions_status"] == "not_checked" for row in _leaves(grouped))


@pytest.mark.parametrize("title", [
    "Model version lookup might be costly", "Model version lookup is already cached",
    "Model version lookup makes a free API call on every recompute",
    PIN + " or signature verification", REPEAT + " and version pinning is absent",
    REPEAT + "; the auth check is absent", REPEAT + " only when the cache expires",
    "If caching fails, " + REPEAT, "Pinning is unnecessary for the model version lookup",
    REPEAT + " " * 2000 + "and a separate issue",
])
def test_unsupported_compound_conditional_and_negative_titles_stay_unresolved(title):
    assert _resolver().identity(_raw(title)) is None
    assert len(dedup_cross_rubric([_finding(_raw(title)), _finding(_raw(REPEAT))])) == 2


@pytest.mark.parametrize("field,value", [
    ("observation", "The model version is not pinned."),
    ("explanation", "The model version is not pinned."),
    ("observation", "The model version lookup is already cached."),
    ("explanation", "Pinning is unnecessary for this model version lookup."),
    ("observation", "The model version lookup is not cached, and secrets leak in logs."),
    ("explanation", "The model version lookup is not cached. Authorization is also missing."),
    ("fix_hint", "Pin the model version ID in configuration."),
    ("fix_hint", "Cache the model version with a TTL and add authentication."),
    ("required_conditions", ["Only when the cache expires"]),
    ("required_conditions", ["The model owner publishes a new version"]),
    ("premises", [{"kind": "authentication_absent"}]),
])
def test_other_claim_fields_cannot_smuggle_a_different_scope_or_polarity(field, value):
    raw = _raw(REPEAT, **{"fix_hint": "Cache the model version with a TTL.", field: value})
    assert _resolver().identity(raw) is None


def test_paid_and_extra_request_qualifiers_do_not_merge_with_plain_repetition():
    titles = [REPEAT, PAID, "Model version lookup adds an extra metadata request on every recompute"]
    rows = [_finding(_raw(title)) for title in titles]
    assert all(row.claim_evidence["source_issue_identity"] for row in rows)
    assert len(dedup_cross_rubric(rows)) == 3


@pytest.mark.parametrize("field,value", [
    ("verification_status", "observed"), ("verification_method", "source_analysis"),
    ("source", "static"), ("origin_category", "Security"), ("context", "test_fixture"),
    ("category", "Security"), ("explanation", "The model version lookup is not cached."),
    ("fix_hint", "Cache the model version with a TTL."),
])
def test_scoped_identity_cannot_erase_different_dispositions_or_ancillary_claims(field, value):
    first = _finding()
    second = replace(first, **{field: value})
    assert len(dedup_cross_rubric([first, second])) == 2


@pytest.mark.parametrize("field,value", [
    ("conditions_status", "observed"), ("consequence_status", "contradicted"),
    ("required_conditions", ["The provider charges for model metadata GET requests"]),
    ("observation", "The model version is not pinned."),
    ("syntax_check", {"kind": "unsupported", "result": "contradicted"}),
    ("premise_checks", [{"kind": "cache_absent", "result": "not_checked"}]),
    ("context_checks", [{"kind": "cost_context", "result": "observed"}]),
    ("recommendation_check", {"result": "prerequisites_required"}),
])
def test_same_scoped_identity_cannot_override_different_evidence(field, value):
    first = _finding()
    evidence = deepcopy(first.claim_evidence)
    evidence[field] = value
    assert len(dedup_cross_rubric([first, replace(first, claim_evidence=evidence)])) == 2


def test_even_supported_condition_paraphrases_are_not_assumed_equivalent():
    conditions = ["The provider charges for model metadata GET requests", "The metadata GET request is billable"]
    rows = [_finding(_raw(required_conditions=[condition])) for condition in conditions]
    assert rows[0].claim_evidence["source_issue_identity"] == rows[1].claim_evidence["source_issue_identity"]
    assert len(dedup_cross_rubric(rows)) == 2


def test_legacy_broad_identity_is_exact_only_and_cannot_reenter_semantic_fallback():
    rows = [_finding(_raw(title), identity=_legacy())
            for title in (REPEAT, "Model version lookup is called on every recompute")]
    assert len(dedup_cross_rubric(rows)) == 2
    rows[1] = replace(rows[0], explanation="A different condition of harm.")
    assert len(dedup_cross_rubric(rows)) == 2


@pytest.mark.parametrize("field,value", [
    ("version", 1), ("version", True), ("version", 3), ("claim_scope", "unknown"),
    ("claim_scope", []), ("claim_scope", {}),
    ("claim_qualifiers", ["not_billable"]), ("source_sha256", "invalid"),
    ("operation_span", [0, 99999]), ("operation_line_start", True),
    ("function_span", [0, 0]), ("method", "model_claim"), ("file", "other.ts"),
])
def test_stale_or_malformed_scoped_identities_cannot_enable_semantic_merge(field, value):
    first = _finding()
    evidence = deepcopy(first.claim_evidence)
    evidence["source_issue_identity"][field] = value
    identity = evidence["source_issue_identity"]
    assert not valid_model_metadata_identity(identity, first.file)
    first = replace(first, claim_evidence=evidence)
    second = replace(first, title="Model version lookup is called on every recompute")
    assert len(dedup_cross_rubric([first, second])) == 2


def test_model_supplied_scope_and_qualifiers_cannot_override_the_claim():
    resolver = _resolver()
    raw = _raw(PIN, source_issue_identity={"claim_scope": "repeated_request"},
               claim_scope="repeated_request", claim_qualifiers=["paid_request_asserted"])
    identity = resolver.identity(raw)
    assert identity["claim_scope"] == "version_selection"
    assert identity["claim_qualifiers"] == []


@pytest.mark.parametrize("field,value", [
    ("source_check", None), ("source_check", {"kind": "not_recorded"}),
    ("source_check", {"kind": "quote_match", "line_start": 900, "line_end": 901}),
    ("source_check", {"kind": "quote_match", "line_start": 2, "line_end": 3, "source_sha256": "f" * 64}),
    ("source_check", {"kind": "quote_match", "line_start": 2, "line_end": 3, "file": "other.ts"}),
    ("source_check", {"kind": "quote_match", "line_start": 2, "line_end": 3, "result": "contradicted"}),
    ("producer", None), ("producer", {"model": "synthetic-model", "rubric": "money", "response": 0}),
    ("producer", {"model": "synthetic-model", "rubric": "money", "response": 1, "source_sha256": "f" * 64}),
])
def test_semantic_paraphrases_need_valid_compatible_quote_and_producer_records(field, value):
    first = _finding()
    evidence = deepcopy(first.claim_evidence)
    evidence[field] = value
    second = replace(first, title="Model version lookup is called on every recompute", claim_evidence=evidence)
    assert len(dedup_cross_rubric([first, second])) == 2


def test_scanner_normalized_null_observation_and_conditions_allow_known_title_paraphrases():
    rows = []
    for title in (REPEAT, "Model version lookup is called on every recompute"):
        raw = _raw(title, evidence="return response.json();")
        row = _finding(raw)
        evidence = {**row.claim_evidence, **model_claim_evidence(raw, {"route.ts": SOURCE})}
        assert evidence["observation"] is None and evidence["required_conditions"] is None
        rows.append(replace(row, claim_evidence=evidence))
    assert len(dedup_cross_rubric(rows)) == 1


@pytest.mark.parametrize("field,value", [
    ("title", "Same lookup with another cost condition"), ("confidence", 0.7),
    ("severity", "high"), ("verification_status", "observed"), ("origin_category", "Security"),
    ("fix_hint", "A distinct recommendation"),
])
def test_legacy_exact_repeat_preserves_every_substantive_field(field, value):
    first = _finding(identity=_legacy())
    second = replace(first, **{field: value})
    assert len(dedup_cross_rubric([first, second])) == 2


def test_supported_metadata_claim_still_requires_an_unambiguous_source_operation():
    resolver = _resolver(SOURCE.replace("  return response.json();", "  await fetch('https://provider.invalid/models/other');"))
    assert resolver.identity(_raw(line_start=2, line_end=2))
    assert resolver.identity(_raw(line_start=2, line_end=3)) is None
    assert _resolver(SOURCE.replace("/models/", "/predictions/")).identity(_raw()) is None


@pytest.mark.parametrize("title", [
    "Model version is unpinned and query has no LIMIT",
    "Model-version lookup is already cached and query has no LIMIT",
    "Query has no LIMIT and the model version is unpinned",
])
def test_rejected_metadata_title_cannot_fall_through_to_another_source_mechanism(title):
    source = SOURCE.replace("  return response.json();", "  return db.from('records').select('*');")
    resolver = _resolver(source)
    mixed = _raw(title, line_start=2, line_end=3)
    pure = _raw("Query has no LIMIT", line_start=3, line_end=3)
    assert resolver.identity(mixed) is None
    query = resolver.identity(pure)
    assert query["mechanism"] == "query_row_bound" and query["version"] == 1
    assert len(dedup_cross_rubric([_finding(mixed, identity=None), _finding(pure, identity=query)])) == 2


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("key,value", [("source_sha256", "f" * 64), ("file", "other.ts")])
def test_metadata_exact_repeat_does_not_bypass_inconsistent_source_records(legacy, key, value):
    first = _finding(identity=_legacy() if legacy else "resolve")
    evidence = deepcopy(first.claim_evidence)
    evidence["source_check"][key] = value
    first = replace(first, claim_evidence=evidence)
    evidence = deepcopy(evidence)
    evidence["producer"]["response"] += 1
    assert len(dedup_cross_rubric([first, replace(first, claim_evidence=evidence)])) == 2


@pytest.mark.parametrize("path", ["", " ", None, [], "../route.ts", "/route.ts"])
def test_metadata_saved_identity_requires_a_valid_nonblank_source_path(path):
    identity = _resolver().identity(_raw())
    identity["file"] = path
    assert not valid_model_metadata_identity(identity, path)
