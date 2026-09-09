"""Synthetic source/response regressions for one network cleanup hypothesis.

No production source, customer report, network service or model API is used.
"""
from copy import deepcopy
from dataclasses import asdict, replace
from hashlib import sha256
import io
import json
import zipfile

import pytest

from app.llm.client import LLMClient, LLMUsage
from app.scan.claim_evidence import model_claim_evidence
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.issue_identity import SourceIssueResolver
from app.scan.llm_scan import run_llm_scan
from app.scan.react_async_context import collect_react_async_context, react_async_premise_checks
from app.scan.react_network_identity import MECHANISM, network_cleanup_identity, valid_network_identity
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.source_facts import facts_prompt
from app.scan.syntax_claims import SyntaxVerifier


BODY = """setSaving(true);
const token = await getToken();
const response = await fetch('/resource', {headers: {Authorization: token}});
const data = await response.json();
setSaved(data.ok);
setSaving(false);
setTimeout(() => setSaved(false), 100);
"""


def source(body=BODY, *, extra="", component="EditorPanel", handler="save", state="saving", setter="setSaving"):
    text = ("import {useState} from 'react';\nexport function " + component + "() {\n"
            "const [saving, setSaving] = useState(false);\nconst [saved, setSaved] = useState(false);\n"
            + extra + "\nconst save = async () => {\n" + body + "\n};\n"
            "return <button disabled={saving} onClick={save}>Save</button>;\n}\n")
    return text.replace("setSaving", setter).replace("saving", state).replace("const save", "const " + handler).replace(
        "onClick={save}", "onClick={" + handler + "}")


def archive(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    out.seek(0)
    return out


def setup(text=None, path="src/Editor.tsx"):
    files = {path: source() if text is None else text}
    buf = archive(files)
    facts = {"react_async": collect_react_async_context(buf)}
    return files, buf, facts


def raw(record, *, variant=0, handler=None, state=None, setter=None):
    handler = handler or record["scope"].rsplit(".", 1)[1]
    binding = next((c for c in record["checks"] if c["kind"] == "react_async_state_reset"), {})
    state = state or binding.get("state", "saving")
    setter = setter or "set" + state[0].upper() + state[1:]
    result = {"file": record["file"], "line_start": record["line"], "line_end": record["line_end"],
              "title": handler[0].upper() + handler[1:] + " handler leaves `" + state + "` stuck on network error",
              "severity": "medium", "confidence": 0.85,
              "evidence": setter + "(true)",
              "observation": "The `" + handler + "` function sets `" + setter + "(true)` on line 10. "
                  "`" + setter + "(false)` on line 20 is only reached on the success path.",
              "required_conditions": ["The fetch call throws a network-level error"],
              "fix_hint": "Wrap the request and reset in try/finally.",
              "explanation": "If the network request in `" + handler + "` throws, the rejection propagates "
                  "out of the async function with no catch block. `" + setter + "(false)` on line 20 is never "
                  "reached, so the button stays disabled until the page is reloaded."}
    if variant:
        result["explanation"] = ("If the fetch throws a network exception, `" + setter + "(false)` on line 20 "
                                 "is never reached. The button stays disabled until the user reloads the page.")
        result["required_conditions"] = [
            "The fetch call throws a network error rather than returning an HTTP error response"]
        result["premises"] = [{"kind": "http_status_guard_absent", "target": handler,
                               "line_start": record["line"], "line_end": record["line_end"]}]
    return result


def row(finding, files, buf, facts, response=1):
    verifier = SyntaxVerifier(buf, facts)
    return ScoredFinding(
        rule_id="llm-web", title=finding["title"], severity="medium", confidence=.85, category="Frontend",
        file=finding["file"], line=finding["line_start"], explanation=finding["explanation"],
        fix_hint=finding["fix_hint"], source="llm", verification_method="model_review",
        claim_evidence={**model_claim_evidence(finding, files),
                        "producer": {"model": "synthetic-model", "rubric": "web", "response": response},
                        "syntax_check": verifier.check(finding),
                        "premise_checks": verifier.premise_checks(finding) + react_async_premise_checks(finding, facts),
                        "source_issue_identity": SourceIssueResolver(buf, facts).identity(finding)})


def pair():
    files, buf, facts = setup()
    rec, = facts["react_async"]["records"]
    return [row(raw(rec, variant=i), files, buf, facts, i + 1) for i in range(2)]


def test_paraphrases_score_once_but_keep_all_pending_premises_and_originals():
    rows = pair()
    before = deepcopy(rows)
    identity = rows[0].claim_evidence["source_issue_identity"]
    assert identity and identity == rows[1].claim_evidence["source_issue_identity"]
    assert identity["mechanism"] == MECHANISM and identity["source_sha256"] == sha256(source().encode()).hexdigest()
    assert valid_network_identity(identity, rows[0].file)
    assert "'/resource'" not in json.dumps(identity) and "Authorization" not in json.dumps(identity)
    result, = dedup_cross_rubric(rows)
    assert compute_scores([result]) == compute_scores(rows[:1])
    assert result.claim_evidence["conditions_status"] == result.claim_evidence["consequence_status"] == "not_checked"
    assert result.verification_status == "unverified"
    originals = result.claim_evidence["grouped_originals"]
    assert originals == [asdict(r) for r in rows]
    assert any(p["kind"] == "http_status_guard_absent" for p in originals[1]["claim_evidence"]["premise_checks"])
    assert rows == before
    assert dedup_cross_rubric([result]) == [result]
    assert dedup_cross_rubric([result] + rows) == [result]


@pytest.mark.parametrize("sentence", [
    "The user can send a request while saving is true.",
    "The button stays disabled before the request.",
    "A network error resets saving but leaves loading true.",
    "The handler leaves saving true and loading stays true.",
    "The handler also ignores HTTP 500 and displays success.",
    "Separately, another user's data is returned.",
    "Malformed JSON leaves the state true.",
    "The fetch is not awaited.",
    "Additionally, another request can overwrite the result.",
    "No error message is displayed.",
    "The success path leaves saving true.",
    "The network error does not leave saving true.",
    "The send button stays disabled.",
    "The recompute embedding button stays disabled.",
    "If the fetch throws, setter_name(false) is never reached, so the button stays disabled.",
])
@pytest.mark.parametrize("field", ["explanation", "observation", "required_conditions"])
def test_independent_compound_and_incompatible_narratives_remain_unresolved(sentence, field):
    files, buf, facts = setup()
    rec, = facts["react_async"]["records"]
    original = raw(rec)
    changed = deepcopy(original)
    if field == "required_conditions":
        changed[field].append(sentence)
    else:
        changed[field] += " " + sentence
    assert network_cleanup_identity(original, facts)
    assert network_cleanup_identity(changed, facts) is None
    assert len(dedup_cross_rubric([row(original, files, buf, facts), row(changed, files, buf, facts, 2)])) == 2


@pytest.mark.parametrize("title", [
    "save leaves saving stuck on HTTP error",
    "save leaves saving stuck on network error and HTTP error",
    "save leaves saving stuck on network error; another state is lost",
    "save leaves loading stuck on network error",
    "other leaves saving stuck on network error",
    "SAVE leaves saving stuck on network error",
    "HTTP save leaves saving stuck on network error",
])
def test_other_title_mechanisms_bindings_and_compounds_cannot_share_network_identity(title):
    _, _, facts = setup()
    finding = raw(facts["react_async"]["records"][0])
    finding["title"] = title
    assert network_cleanup_identity(finding, facts) is None


@pytest.mark.parametrize("body", [
    "setSaving(true); await fetch('/one'); await fetch('/two'); setSaving(false);",
    "setSaving(true); await fetch('/one'); const later = () => fetch('/two'); setSaving(false);",
    "setSaving(true); const request = fetch; await request('/one'); setSaving(false);",
    "setSaving(true); await fetch?.('/one'); setSaving(false);",
    "setSaving(true); if (ready) await fetch('/one'); setSaving(false);",
    "setSaving(true); await fetch('/one'); if (ready) setSaving(false);",
    "setSaving(true); try { await fetch('/one'); } catch { setSaving(false); }",
    "setSaving(true); try { await fetch('/one'); } finally { setSaving(false); }",
    "setSaving(true); await fetch('/one'); setSaving(false); const later = () => setSaving(true);",
    "setSaving(true); await fetch('/one'); setSaving(false); mutate(setSaving);",
    "setSaving(true); return; await fetch('/one'); setSaving(false);",
])
def test_ambiguous_or_guarded_source_paths_keep_existing_counterchecks_without_identity(body):
    _, _, facts = setup(source(body))
    rec = facts["react_async"]["records"][0]
    assert network_cleanup_identity(raw(rec), facts) is None
    if "catch { setSaving(false); }" in body:
        finding = raw(rec)
        finding["title"] = "save leaves saving stuck on network error"
        assert react_async_premise_checks(finding, facts)[0]["result"] == "contradicted"


@pytest.mark.parametrize("extra", [
    "const fetch = custom;", "const stateAlias = setSaving;", "function other(setSaving) {}",
    "globalThis.fetch = custom;", "const globalAlias = window; globalAlias.fetch = custom;",
    "const Save = async () => { setSaving(true); await fetch('/other'); setSaving(false); };",
])
def test_shadowed_escaped_or_case_ambiguous_source_bindings(extra):
    _, _, facts = setup(source(extra=extra))
    rec = next(r for r in facts["react_async"]["records"] if r["scope"].endswith(".save"))
    identity = network_cleanup_identity(raw(rec), facts)
    if extra == "const stateAlias = setSaving;":
        # Escaping in the component can affect lifecycle behavior, but the
        # inventory identifies only direct writes in this handler, not safety.
        assert identity is not None
    else:
        assert identity is None


@pytest.mark.parametrize(("field", "value"), [
    ("source", "static"), ("verification_method", "source_pattern"), ("verification_status", "observed"),
    ("category", "Security"), ("origin_category", "Security"),
])
def test_same_source_identity_does_not_merge_incompatible_finding_dispositions(field, value):
    left, right = pair()
    assert len(dedup_cross_rubric([left, replace(right, **{field: value})])) == 2


@pytest.mark.parametrize(("kind", "value"), [
    ("syntax_check", {"kind": "react_async_network_reset_absent", "result": "contradicted"}),
    ("recommendation_check", {"result": "prerequisites_required"}),
    ("conditions_status", "observed"), ("consequence_status", "contradicted"),
    ("premise_checks", [{"kind": "react_async_network_reset_absent", "target": "saving", "result": "contradicted"}]),
])
def test_same_source_identity_does_not_merge_incompatible_evidence(kind, value):
    left, right = pair()
    evidence = deepcopy(right.claim_evidence)
    evidence[kind] = value
    assert len(dedup_cross_rubric([left, replace(right, claim_evidence=evidence)])) == 2


@pytest.mark.parametrize(("key", "value"), [
    ("result", "observed"), ("result", "contradicted"), ("target", "response"),
    ("kind", "json_rejection_uncaught"), ("whole_finding", True), ("claim_scope", "compound"),
    ("line_start", True), ("line_end", 99999), ("anchor_line_start", 1),
])
def test_http_premise_exception_is_limited_to_pending_handler_request(key, value):
    left, right = pair()
    evidence = deepcopy(right.claim_evidence)
    evidence["premise_checks"][0][key] = value
    assert len(dedup_cross_rubric([left, replace(right, claim_evidence=evidence)])) == 2


@pytest.mark.parametrize("missing", ["handler", "handler_line_start", "state", "source_sha256", "function_span"])
def test_malformed_saved_identities_fail_closed_without_crashing(missing):
    rows = pair()
    for i, r in enumerate(rows):
        evidence = deepcopy(r.claim_evidence)
        del evidence["source_issue_identity"][missing]
        rows[i] = replace(r, claim_evidence=evidence)
    assert len(dedup_cross_rubric(rows)) == 2


def test_source_digest_operation_handler_and_state_distinguish_identities():
    ids = []
    for index, text in enumerate([
        source(), source().replace("'/resource'", "'/another-resource'"),
        source(handler="update"), source(state="busy", setter="setBusy"),
    ]):
        _, _, facts = setup(text)
        rec, = facts["react_async"]["records"]
        ids.append(network_cleanup_identity(raw(rec), facts))
    assert all(ids) and len({json.dumps(identity, sort_keys=True) for identity in ids}) == 4


def test_missing_facts_forged_model_identity_and_overlong_prose_cannot_supply_identity():
    files, buf, facts = setup()
    finding = raw(facts["react_async"]["records"][0])
    expected = network_cleanup_identity(finding, facts)
    finding["claim_evidence"] = {"source_issue_identity": {"mechanism": "invented"}}
    finding["source_issue_identity"] = {"mechanism": "invented"}
    assert SourceIssueResolver(buf, facts).identity(finding) == expected
    assert SourceIssueResolver(buf).identity(finding) is None
    finding["explanation"] += " " * 16001 + "Another defect."
    assert SourceIssueResolver(buf, facts).identity(finding) is None


def test_stale_source_facts_cannot_identify_a_different_submitted_archive():
    files, _, facts = setup()
    finding = raw(facts["react_async"]["records"][0])
    changed = {path: text.replace("'/resource'", "'/different'") for path, text in files.items()}
    assert network_cleanup_identity(finding, facts) is not None
    assert SourceIssueResolver(archive(changed), facts).identity(finding) is None


class Responses(LLMClient):
    def __init__(self, replies):
        super().__init__(providers=[])
        self.replies, self.calls = replies, 0

    def complete(self, system, user, max_tokens=4096):
        answer = self.replies[self.calls]
        self.calls += 1
        return json.dumps(answer), LLMUsage(model="synthetic-model", input_tokens=100, output_tokens=10)


def test_two_pass_scan_merges_four_source_pairs_without_static_or_http_overlap():
    specs = [("EditorPanel", "save", "saving", "setSaving"),
             ("ComputePanel", "compute", "working", "setWorking"),
             ("TestConversationTab", "send", "loading", "setLoading"),
             ("HintPanel", "suggest", "suggesting", "setSuggesting")]
    files = {f"src/Panel{index}.tsx": source(component=c, handler=h, state=s, setter=set_s)
             for index, (c, h, s, set_s) in enumerate(specs)}
    buf = archive(files)
    facts = {"react_async": collect_react_async_context(buf)}
    replies = [[raw(record, variant=variant) for record in facts["react_async"]["records"]] for variant in (0, 1)]
    for reply in replies:
        reply[2]["title"] = "Test-conversation send handler leaves `loading` stuck on network error"
    before = deepcopy(replies)
    client = Responses(replies)
    result, stats = run_llm_scan(buf, client, rubrics=("web",), passes=2, source_facts=facts)
    assert client.calls == stats.calls == 2
    assert stats.verified == 8 and stats.discarded == 0 and len(result) == 4
    assert replies == before
    assert all(len(f.claim_evidence["grouped_originals"]) == 2 for f in result)
    assert len({json.dumps(f.claim_evidence["source_issue_identity"], sort_keys=True) for f in result}) == 4
    # New binding metadata is a scanner comparison input, not more prompt text.
    prompt = facts_prompt(facts)
    assert "network_cleanup_bindings" not in prompt and "source_sha256" not in prompt
