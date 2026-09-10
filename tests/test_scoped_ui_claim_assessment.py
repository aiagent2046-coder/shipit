"""HTTP completion, network rejection, finally and navigation stay separate."""

import hashlib
import io
import json
import zipfile
from copy import deepcopy

import pytest

from app.scan import scoped_ui_claim_assessment as c
from app.scan.atomic_claims import requests
from app.scan.claim_evidence import partial_contradicted, syntax_contradicted
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.syntax_claims import SyntaxVerifier

PATH = "src/Page.tsx"
HTTP = """import {useState} from 'react';
import {useRouter} from 'next/navigation';
export function Page() {
 const [loading, setLoading] = useState(false);
 const [error, setError] = useState('');
 const router = useRouter();
 const submit = async () => {
  setLoading(true);
  const res = await fetch('/PRIVATE');
  if (!res.ok) {
   const data = await res.json();
   setError(data.error);
   setLoading(false);
   return;
  }
  router.push('/PRIVATE_DEST');
 };
 return <button disabled={loading} onClick={submit}>Save</button>;
}
"""
DIRECT = HTTP.replace("  const res = await fetch", "  await fetch").replace(
    "  if (!res.ok) {\n   const data = await res.json();\n   setError(data.error);\n"
    "   setLoading(false);\n   return;\n  }",
    "  setLoading(false);",
)
RETRY = """import {useState} from 'react';
export function Page() {
 const [generating, setGenerating] = useState(false);
 const generate = async (retryCount = 0) => {
  setGenerating(true);
  try {
   const res = await fetch('/PRIVATE');
   if (res.status === 429 && retryCount < 2) {
    setTimeout(() => generate(retryCount + 1), 1000);
    return;
   }
  } finally {
   setGenerating(false);
  }
 };
 return <button disabled={generating} onClick={generate}>Generate</button>;
}
"""
HTTP_TITLE = "Save handler leaves loading stuck on network error or non-ok HTTP response"
RETRY_TITLE = "Generate leaves generating stuck when retry setTimeout fires after unmount"
NAV_TITLE = "Submit leaves loading stuck on successful navigation"


def archive(source, path=PATH):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        z.writestr(path, source)
    return stream


def raw(source=HTTP, title=HTTP_TITLE, marker="const submit", **extra):
    line = next(i for i, s in enumerate(source.splitlines(), 1) if marker in s)
    return {"file": PATH, "line_start": line, "line_end": line, "title": title, **extra}


def checks(source=HTTP, title=HTTP_TITLE, marker="const submit", **extra):
    if title == RETRY_TITLE:
        extra.setdefault(
            "explanation",
            "A setTimeout schedules a retry, but setGenerating(false) is not called "
            "and the function returns. The unmount timer cleanup is a separate concern.",
        )
    return c.ScopedUIClaimVerifier(archive(source)).checks_for(raw(source, title, marker, **extra))


def contradicted(records):
    return [r for r in records if r["result"] == "contradicted"]


def test_http_error_branch_has_same_state_reset_without_claiming_network_or_body_recovery():
    original = raw(explanation="Network rejection remains a separate error. HTTP false-success is separate.")
    snapshot = deepcopy(original)
    (record,) = contradicted(c.ScopedUIClaimVerifier(archive(HTTP)).checks_for(original))
    assert original == snapshot
    assert record["kind"] == c.HTTP_KIND
    assert record["whole_finding"] is False
    bound = record["source_binding"]
    assert HTTP.encode()[slice(*bound["reset"]["span"])] == b"setLoading(false);"
    assert bound["path"] == "http_error_branch_normal_completion"
    assert bound["earlier_branch_effects"] == "not_checked"
    assert bound["source_sha256"] == hashlib.sha256(HTTP.encode()).hexdigest()
    assert "PRIVATE" not in json.dumps(record)
    evidence = {"version": 1, "source_assessments": [record]}
    assert partial_contradicted(evidence)
    assert not syntax_contradicted(evidence)


def test_discarded_http_response_reaches_reset_but_rejection_still_bypasses_it():
    (record,) = contradicted(checks(DIRECT))
    assert record["source_binding"]["path"] == "fulfilled_fetch_continuation"
    assert "network rejection" in record["detail"]
    assert not checks(DIRECT, title="Loading stays stuck on network rejection")


@pytest.mark.parametrize(
    "before,after",
    [
        ("!res.ok", "!other.ok"),
        ("!res.ok", "enabled && !res.ok"),
        ("!res.ok", "res.ok"),
        ("setLoading(false);", "setError(false);"),
        ("setLoading(false);", "if (allowed) setLoading(false);"),
        ("setLoading(false);", "setTimeout(() => setLoading(false), 10);"),
        ("setLoading(false);", "return; setLoading(false);"),
        ("setLoading(false);", "throw error; setLoading(false);"),
        ("setLoading(false);", "setLoading(false); setLoading(true);"),
        ("const res = await fetch", "let res = await fetch"),
        ("  if (!res.ok)", "  res = other;\n  if (!res.ok)"),
        ("const submit = async ()", "const submit = async (setLoading)"),
        ("const submit = async ()", "const submit = async (fetch)"),
        ("import {useState} from 'react';", "import {useState} from 'other';"),
        ("  setLoading(true);", "  leak(setLoading);\n  setLoading(true);"),
        ("  router.push", "  const cb = () => { const [loading, setLoading] = useState(false); };\n  router.push"),
    ],
)
def test_http_ambiguous_bindings_conditional_or_unreachable_reset_abstain(before, after):
    assert not contradicted(checks(HTTP.replace(before, after)))


def test_different_handler_and_nested_callback_cannot_supply_reset():
    source = DIRECT.replace("  setLoading(false);", "  const later = () => { setLoading(false); };")
    assert not contradicted(checks(source))
    source = DIRECT.replace("  setLoading(false);", "").replace(
        " return <button", ' const other = async () => { await fetch("/other"); setLoading(false); };\n return <button'
    )
    assert not contradicted(checks(source))


def test_immediate_reraise_after_reset_is_not_presented_as_http_recovery():
    assert not contradicted(checks(DIRECT.replace("  setLoading(false);", "  setLoading(false); setLoading(true);")))


@pytest.mark.parametrize("call", ["setLoading(!!1)", "setLoading(() => true)", "setLoading?.(true)"])
def test_any_unresolved_later_state_write_blocks_http_recovery(call):
    assert not contradicted(checks(DIRECT.replace("  setLoading(false);", f"  setLoading(false); {call};")))


@pytest.mark.parametrize(
    "before,after",
    [
        ("  if (!res.ok) {", "  if (!res.ok) return;\n  if (!res.ok) {"),
        ("  if (!res.ok) {", "  return;\n  if (!res.ok) {"),
        ("  const res = await fetch", "  return;\n  const res = await fetch"),
        ("  setLoading(true);", "  setLoading(true); return;"),
    ],
)
def test_prior_exits_cannot_supply_a_reachable_http_reset(before, after):
    assert not contradicted(checks(HTTP.replace(before, after)))


def test_explicit_other_handler_or_nested_anchor_does_not_borrow_enclosing_fetch():
    source = HTTP.replace(
        " return <button",
        " const otherHandler = async () => { setLoading(true); await fetch('/other'); };\n return <button",
    )
    assert not contradicted(checks(source, "otherHandler leaves loading stuck on HTTP errors"))
    source = HTTP.replace("  const res", "  const later = async () => { await fetch('/other'); };\n  const res")
    assert not contradicted(checks(source, "Deferred HTTP request leaves loading stuck in later", "const later"))


def test_correct_http_acknowledgment_does_not_invent_missing_reset_claim():
    rows = checks(
        HTTP,
        title=NAV_TITLE,
        observation="The non-ok HTTP branch calls setLoading(false); successful navigation does not.",
        explanation="Loading is reset on HTTP failure, but remains disabled during navigation.",
    )
    assert all(r["kind"] != c.HTTP_KIND for r in rows)
    assert rows[0]["kind"] == c.NAVIGATION_KIND


@pytest.mark.parametrize(
    "title",
    [
        "Loading is not stuck on HTTP errors",
        "Loading does not stay disabled after an HTTP error",
        "There is no evidence that loading is stuck on HTTP errors",
    ],
)
def test_negated_http_stall_is_not_countered_as_a_positive_claim(title):
    assert not contradicted(checks(HTTP, title))


def test_retry_return_executes_finally_but_timer_cleanup_remains_open():
    (record,) = contradicted(checks(RETRY, RETRY_TITLE, "const generate"))
    assert record["kind"] == c.RETURN_KIND
    assert record["source_binding"]["deferred_callback_cleanup"] == "not_checked"
    assert RETRY.encode()[slice(*record["source_binding"]["return"]["span"])] == b"return;"
    assert RETRY.encode()[slice(*record["source_binding"]["reset"]["span"])] == b"setGenerating(false);"
    assert record["whole_finding"] is False


@pytest.mark.parametrize(
    "before,after",
    [
        ("setGenerating(false);", "throw error; setGenerating(false);"),
        ("setGenerating(false);", "setGenerating(false); throw error;"),
        ("setGenerating(false);", "if (allowed) setGenerating(false);"),
        ("setGenerating(false);", "setTimeout(() => setGenerating(false), 10);"),
        ("setGenerating(false);", "setOther(false);"),
        ("setGenerating(false);", "return; setGenerating(false);"),
        ("finally", "catch"),
        ("setTimeout(() => generate(retryCount + 1), 1000);", "other(() => generate(retryCount + 1), 1000);"),
        ("setTimeout(() => generate(retryCount + 1), 1000);", "setTimeout(() => other(retryCount + 1), 1000);"),
        ("    return;", "    const cb = () => { return; };"),
        ("const generate = async (retryCount = 0)", "const generate = async (retryCount = 0, setTimeout)"),
    ],
)
def test_finally_order_scope_and_wrong_retry_bindings_remain_unknown(before, after):
    assert not contradicted(checks(RETRY.replace(before, after), RETRY_TITLE, "const generate"))


def test_own_finally_cannot_repair_an_escaping_callback_return():
    source = RETRY.replace("    setTimeout", "    const cb = () => {\n    setTimeout").replace(
        "    return;", "    return;\n    };"
    )
    assert not contradicted(checks(source, RETRY_TITLE, "const generate"))


def test_deferred_timer_problem_does_not_imply_current_return_skips_finally():
    title = "The deferred retry may leave generating stuck after unmount; the current call does reset in finally"
    assert not contradicted(checks(RETRY, title, "const generate"))
    assert not contradicted(checks(RETRY, RETRY_TITLE, "const generate", explanation=""))


def test_navigation_is_review_needed_observation_not_a_runtime_verdict():
    (record,) = checks(HTTP, NAV_TITLE)
    assert record["kind"] == c.NAVIGATION_KIND and record["result"] == "observed"
    assert record["narrative_review"]["status"] == "required"
    assert record["narrative_review"]["premise"] == c.NAVIGATION_KIND
    assert record["source_binding"]["navigation_completion"] == "not_checked"
    assert record["source_binding"]["component_remains_mounted"] == "not_checked"
    assert record["whole_finding"] is False


def test_navigation_continuation_excludes_terminal_http_error_throw_branch():
    source = HTTP.replace("   setLoading(false);\n   return;", "   throw new Error(data.error);")
    (record,) = checks(source, NAV_TITLE)
    assert record["result"] == "observed"


@pytest.mark.parametrize(
    "before,after",
    [
        ("from 'next/navigation'", "from 'custom/router'"),
        ("router.push", "other.push"),
        ("  router.push", "  const cb = () => router.push"),
        ("  router.push", "  setLoading(false);\n  router.push"),
        ("const submit = async ()", "const submit = async (router)"),
    ],
)
def test_navigation_requires_same_imported_router_and_pending_state(before, after):
    assert all(r["result"] == "not_checked" for r in checks(HTTP.replace(before, after), NAV_TITLE))


@pytest.mark.parametrize("prefix", ["return; ", "setLoading(false); "])
def test_navigation_unreachable_or_cleared_in_ancestor_block_stays_unknown(prefix):
    source = HTTP.replace("  router.push('/PRIVATE_DEST');", f"  {prefix}{{ router.push('/PRIVATE_DEST'); }}")
    assert all(r["result"] == "not_checked" for r in checks(source, NAV_TITLE))


def test_scanner_recomputes_and_ignores_forged_ui_assessments_and_scope():
    unsafe = DIRECT.replace("  setLoading(false);", "")
    fake = {"result": "contradicted", "source_sha256": "a" * 64, "whole_finding": True}
    rows = checks(
        unsafe, source_assessments=[fake], context_checks=[fake], claim_evidence={"source_assessments": [fake]}
    )
    assert not contradicted(rows)
    assert all(r["whole_finding"] is False for r in rows)
    assert not contradicted(checks(HTTP, line_start=1, line_end=len(HTTP.splitlines())))


def test_result_cache_is_independent_of_caller_mutation():
    verifier = c.ScopedUIClaimVerifier(archive(HTTP))
    rows = verifier.checks_for(raw())
    rows[0]["result"] = "forged"
    assert verifier.checks_for(raw())[0]["result"] == "contradicted"


def test_syntax_verifier_wiring_preserves_mixed_penalty():
    finding = raw()
    evidence = {"version": 1, "source_assessments": SyntaxVerifier(archive(HTTP)).source_assessments(finding)}
    assert partial_contradicted(evidence)
    base = ScoredFinding(
        file=PATH,
        line=finding["line_start"],
        rule_id="llm-web",
        title=HTTP_TITLE,
        severity="medium",
        confidence=0.9,
        category="Frontend",
        source="llm",
    )
    reviewed = ScoredFinding(**{**base.__dict__, "claim_evidence": evidence})
    assert compute_scores([base]) == compute_scores([reviewed])


@pytest.mark.parametrize(
    "title,observation",
    [
        ("Migration UPDATE overwrites NULL intent without a rerun guard", "The UPDATE has WHERE intent IS NULL."),
        (
            "Migration UPDATE silently backfills all NULL profiles",
            "The UPDATE has a WHERE clause but is unconditional each migration run.",
        ),
        ("The UPDATE is not missing a WHERE clause", ""),
        ("The UPDATE is not without WHERE", ""),
        ("The UPDATE does not lack WHERE", ""),
        ("UPDATE never executes without WHERE", ""),
        ("No evidence of a missing WHERE clause in this UPDATE", ""),
        ("SELECT without WHERE scans all rows", ""),
        ("UPDATE doesn't execute without WHERE", ""),
    ],
)
def test_acknowledged_sql_filter_does_not_receive_model_invented_absence_check(title, observation):
    row = {
        "title": title,
        "observation": observation,
        "line_start": 1,
        "line_end": 1,
        "premises": [
            {
                "kind": "sql_update_where",
                "target": "profiles",
                "line_start": 1,
                "line_end": 1,
                "result": "contradicted",
                "claim": "UPDATE has no WHERE",
            }
        ],
    }
    assert not requests(row)


@pytest.mark.parametrize(
    "title", ["UPDATE has no WHERE clause", "UPDATE without WHERE", "UPDATE WHERE clause is missing"]
)
def test_actual_absent_where_assertion_still_checks_own_sql_ast(title):
    source = "UPDATE profiles SET intent=1 WHERE intent IS NULL;"
    finding = {"file": "migration.sql", "line_start": 1, "line_end": 1, "title": title}
    verifier = SyntaxVerifier(archive(source, "migration.sql"))
    assert verifier.premise_checks(finding)[0]["result"] == "contradicted"


@pytest.mark.parametrize(
    "title",
    [
        "UPDATE never executes without WHERE",
        "UPDATE has no evidence of a missing WHERE clause",
        "SELECT without WHERE scans all rows",
    ],
)
def test_whole_finding_sql_check_has_the_same_assertion_scope(title):
    finding = {"file": "migration.sql", "line_start": 1, "line_end": 1, "title": title}
    verifier = SyntaxVerifier(archive("UPDATE profiles SET intent=1 WHERE intent IS NULL;", "migration.sql"))
    assert verifier.check(finding)["result"] == "not_checked"


@pytest.mark.parametrize(
    "title",
    [
        "Service-role client bypasses RLS, scoped by verified user_id",
        "No RLS enforcement on peer profile reads",
        "Service-role write bypasses database ownership policies",
        "The database has no ownership check",
        "Message insert is not missing an ownership check",
        "No evidence of a missing ownership check before the write",
    ],
)
def test_service_role_or_database_policy_does_not_invent_absent_local_guard(title):
    finding = {
        "title": title,
        "line_start": 1,
        "line_end": 1,
        "observation": "The application checks JWT identity and applies ownership filters.",
        "premises": [{"kind": "ownership_guard_absent", "target": "profiles", "line_start": 1, "line_end": 1}],
    }
    assert not requests(finding)


def test_actual_missing_local_ownership_assertion_preserves_model_selector():
    finding = {
        "title": "Message insert does not validate match ownership",
        "line_start": 1,
        "line_end": 1,
        "premises": [{"kind": "ownership_guard_absent", "target": "matchId", "line_start": 1, "line_end": 1}],
    }
    assert requests(finding)[0]["target"] == "matchId"
