"""Generated compositions and counterexamples for source-bound network grouping.

Fixtures are synthetic; no customer code or saved provider responses belong here.
"""
from copy import deepcopy
from dataclasses import asdict, replace
from itertools import permutations

import pytest

from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.react_network_claims import project_network_claim
from app.scan.react_network_identity import network_cleanup_identity
from app.scan.scoring import compute_scores
from tests.test_react_network_identity import raw, row, setup, source


def scene(*, component="ComposerPane", handler="submit", state="busy", setter="setBusy", visible=True):
    text = source(component=component, handler=handler, state=state, setter=setter)
    if visible:
        text = text.replace("return <button", f"return <><span>{{{state} && <i>Working</i>}}</span><button")
        text = text.replace("</button>;", "</button></>;")
    files, buf, facts = setup(text, f"src/{component}.tsx")
    rec, = facts["react_async"]["records"]
    return files, buf, facts, rec


@pytest.mark.parametrize(("component", "handler", "state", "setter"), [
    ("ComposerPane", "submit", "busy", "setBusy"),
    ("LedgerPanel", "persist", "pending", "markPending"),
    ("AssetPage", "upload", "working", "setWorking"),
    ("QueueTab", "enqueue", "waiting", "setWaiting"),
])
@pytest.mark.parametrize("order", list(permutations(range(3))))
def test_independent_clause_compositions_keep_source_identity(component, handler, state, setter, order):
    files, buf, facts, rec = scene(component=component, handler=handler, state=state, setter=setter)
    original = raw(rec, setter=setter)
    changed = deepcopy(original)
    changed["title"] = f"{handler} keeps {state}=true stuck after a network rejection"
    atoms = [f"In {component}, the {handler} handler sets {setter}(true) before the fetch",
             "the fetch call is awaited on line 20",
             f"{setter}(false) is only reached on the success path"]
    changed["observation"] = "; and then ".join(atoms[i] for i in order) + ". No catch or finally block."
    changed["explanation"] = ("When the fetch request rejects with a transport failure, "
                              f"{setter}(false) is not reached. "
                              f"The {handler} button remains disabled and the spinner remains visible "
                              "until the user reloads.")
    changed["required_conditions"] = ["The fetch call rejects with a network exception "
                                      "(rejected promise, not an HTTP error response)"]
    rows = [row(f, files, buf, facts, i + 1) for i, f in enumerate([original, changed])]
    assert all(r.claim_evidence["source_issue_identity"] for r in rows)
    grouped, = dedup_cross_rubric(rows)
    assert compute_scores([grouped]) == compute_scores(rows[:1])
    assert grouped.claim_evidence["grouped_originals"] == [asdict(r) for r in rows]
    assert dedup_cross_rubric([grouped] + rows) == [grouped]
    assert all(f["claim_evidence"]["consequence_status"] == "not_checked"
               for f in grouped.claim_evidence["grouped_originals"])


def test_source_json_sequence_and_network_examples_do_not_split_at_member_dot():
    files, buf, facts, rec = scene()
    one = raw(rec)
    two = deepcopy(one)
    two["observation"] = ("setBusy(true) is set before the fetch. setBusy(false) is only reached "
                           "after a successful response.json() call. There is no catch or finally block.")
    two["required_conditions"] = ["The fetch call throws a network failure (not an HTTP error response, "
                                  "but a rejected promise — e.g. offline, DNS failure, timeout)"]
    grouped, = dedup_cross_rubric([row(one, files, buf, facts), row(two, files, buf, facts, 2)])
    assert len(grouped.claim_evidence["grouped_originals"]) == 2
    assert "response.json()" in grouped.claim_evidence["grouped_originals"][1]["claim_evidence"]["observation"]


@pytest.mark.parametrize("clause", [
    "When response.json() rejects, setBusy(false) is not reached.",
    "The fetch returns an HTTP error response and the button stays disabled.",
    "When the fetch succeeds, setBusy(false) is not reached.",
    "The network request does not throw.",
    "The fetch call throws a network error only after another request overwrites the state.",
    "The fetch call throws a network error (not an HTTP error response) and saves corrupt data.",
    "The user can retry while busy is true.",
    "setSaved(false) is never reached.",
    "The delete button remains disabled.",
    "The user is billed repeatedly.",
    "The spinner remains visible before the fetch.",
    "The fetch call is not awaited.",
    "No catch or finally block resets it, but there is a second missing guard.",
    "The button stays disabled if the user has a different role.",
    "BOUNDSETTER(false) is never reached.",
    "The fetch call throws a network error (not an HTTP error response, but a JSON error).",
    "The fetch call throws a network error. setBusy(false) is only on the success path. Unknown.",
])
@pytest.mark.parametrize("field", ["observation", "explanation", "required_conditions"])
def test_residual_claims_or_changed_polarity_never_disappear_inside_group(clause, field):
    files, buf, facts, rec = scene()
    one, two = raw(rec), raw(rec)
    if field == "required_conditions":
        two[field].append(clause)
    else:
        two[field] += " " + clause
    assert network_cleanup_identity(one, facts)
    assert network_cleanup_identity(two, facts) is None
    assert len(dedup_cross_rubric([row(one, files, buf, facts), row(two, files, buf, facts, 2)])) == 2


@pytest.mark.parametrize("expression", ["busy || !saved", "(busy || !saved)", "!saved || busy"])
def test_same_flag_in_closed_disabled_or_is_a_supported_subordinate_role(expression):
    text = source(state="busy", setter="setBusy").replace("disabled={busy}", "disabled={" + expression + "}")
    _, _, facts = setup(text)
    rec, = facts["react_async"]["records"]
    assert network_cleanup_identity(raw(rec), facts)
    assert rec["controls"][0]["truthy_disabled_states"] == ["busy"]


@pytest.mark.parametrize("expression", [
    "busy && saved", "external() || busy", "busy || external()", "busy ? saved : false", "!busy",
])
def test_other_boolean_relations_or_unknown_effects_do_not_establish_same_disabled_role(expression):
    text = source(state="busy", setter="setBusy").replace("disabled={busy}", "disabled={" + expression + "}")
    _, _, facts = setup(text)
    rec, = facts["react_async"]["records"]
    assert network_cleanup_identity(raw(rec), facts) is None


@pytest.mark.parametrize("mutation", ["other_response", "no_json_call", "other_visible_state", "no_visible_state"])
def test_subordinate_source_roles_need_the_actual_response_or_same_state(mutation):
    files, _, _, _ = scene()
    path, text = next(iter(files.items()))
    if mutation == "other_response":
        text = text.replace("response.json()", "unrelated.json()")
    elif mutation == "no_json_call":
        text = text.replace("await response.json()", "{}")
    elif mutation == "other_visible_state":
        text = text.replace("busy && <i>", "saved && <i>")
    else:
        text = text.replace("busy && <i>", "false && <i>")
    _, _, facts = setup(text, path)
    rec, = facts["react_async"]["records"]
    finding = raw(rec)
    if mutation in {"other_response", "no_json_call"}:
        finding["observation"] += " setBusy(false) is only reached after a successful response.json() call."
    else:
        finding["explanation"] += " The spinner stays visible."
    assert network_cleanup_identity(finding, facts) is None


def test_explicit_source_scope_resolves_wrong_display_handler_and_keeps_disagreement():
    files, buf, facts = setup(source(component="AccountPanel", handler="persist"), "src/account/Page.tsx")
    rec, = facts["react_async"]["records"]
    one = raw(rec)
    two = deepcopy(one)
    two["title"] = "Account refresh handler leaves saving stuck on network error"
    two["observation"] = "In AccountPanel, the persist function calls setSaving(true) before the fetch."
    rows = [row(one, files, buf, facts), row(two, files, buf, facts, 2)]
    grouped, = dedup_cross_rubric(rows)
    scope = grouped.claim_evidence["grouped_claim_scope"]
    assert scope["title_source_disagreements"] == [
        {"original_index": 1, "result": "different_handler_label", "source_handler": "persist"}]
    assert grouped.claim_evidence["grouped_originals"] == [asdict(r) for r in rows]
    assert dedup_cross_rubric([grouped]) == [grouped]
    two["observation"] = two["observation"].replace("In AccountPanel, ", "")
    assert network_cleanup_identity(two, facts) is None


def test_distinct_consequence_disposition_cannot_be_erased_by_same_source_group():
    files, buf, facts, rec = scene()
    one = row(raw(rec), files, buf, facts)
    other = replace(one, claim_evidence={**one.claim_evidence, "consequence_status": "contradicted"})
    assert len(dedup_cross_rubric([one, other])) == 2


def test_parser_refuses_over_budget_unknown_text_and_malformed_values():
    kwargs = dict(component="Panel", handler="save", state="busy", setter="setBusy", has_button=True)
    assert project_network_claim(None, **kwargs) is None
    assert project_network_claim("No catch block. " * 65, **kwargs) is None
    assert project_network_claim("No catch block." + " " * 16000, **kwargs) is None


@pytest.mark.parametrize("field", ["explanation", "observation", "required_conditions", "premises"])
@pytest.mark.parametrize("value", [False, {}, 0])
def test_falsy_malformed_values_do_not_become_empty_valid_claims(field, value):
    _, _, facts, rec = scene()
    finding = raw(rec)
    finding[field] = value
    assert network_cleanup_identity(finding, facts) is None


@pytest.mark.parametrize("body", [
    "setSaving(true); const response = await fetch('/resource'); "
    "if (false) { await response.json(); } setSaving(false);",
    "setSaving(true); const response = await fetch('/resource'); "
    "for (const item of []) { await response.json(); } setSaving(false);",
    "setSaving(true); const response = await fetch('/resource'); "
    "ready && await response.json(); setSaving(false);",
])
def test_conditional_json_cannot_support_success_sequencing_claim(body):
    files, buf, facts = setup(source(body))
    rec, = facts["react_async"]["records"]
    original = raw(rec)
    changed = deepcopy(original)
    changed["observation"] += " setSaving(false) is only reached after a successful response.json() call."
    assert network_cleanup_identity(original, facts)
    assert network_cleanup_identity(changed, facts) is None
    assert len(dedup_cross_rubric([row(original, files, buf, facts), row(changed, files, buf, facts, 2)])) == 2


@pytest.mark.parametrize("element", [
    '<i hidden>Loading</i>', '<i aria-hidden="true">Loading</i>',
    '<i style={{display:"none"}}>Loading</i>', '<i style={{opacity:0}}>Loading</i>',
    '<i style={{fontSize:0}}>Loading</i>', '<i style={{color:"transparent"}}>Loading</i>',
    '<i style={style}>Loading</i>', '<i {...props}>Loading</i>',
    '<Spinner>Loading</Spinner>', '<i>Done</i>', '<i>Not loading</i>', '<i>Loading complete</i>',
    '<i>{unknownText}</i>',
])
def test_hidden_unknown_or_non_status_elements_do_not_support_visible_consequence(element):
    files, _, _, _ = scene()
    path, text = next(iter(files.items()))
    text = text.replace('<i>Working</i>', element)
    _, _, facts = setup(text, path)
    rec, = facts["react_async"]["records"]
    finding = raw(rec)
    assert network_cleanup_identity(finding, facts)
    finding["explanation"] += " The spinner stays visible."
    assert network_cleanup_identity(finding, facts) is None


@pytest.mark.parametrize("mutation", ["hidden_parent", "custom_parent", "unused", "unreachable"])
def test_status_element_needs_native_return_ancestry_without_local_hiding(mutation):
    files, _, _, _ = scene()
    path, text = next(iter(files.items()))
    if mutation == "hidden_parent":
        text = text.replace("<span>", "<span hidden>")
    elif mutation == "custom_parent":
        text = text.replace("<span>", "<Container>").replace("</span>", "</Container>")
    elif mutation == "unused":
        text = text.replace("return <>", "const unused = <>").replace("</>;", "</>; return <p>Done</p>;")
    else:
        text = text.replace("{busy && <i>Working</i>}", "{false && <div>{busy && <i>Working</i>}</div>}")
    _, _, facts = setup(text, path)
    rec, = facts["react_async"]["records"]
    finding = raw(rec)
    finding["explanation"] += " The spinner stays visible."
    assert network_cleanup_identity(finding, facts) is None


def test_throwing_trim_before_flag_cannot_supply_a_disabled_consequence():
    text = source().replace("disabled={saving}", "disabled={!saved.trim() || saving}")
    _, _, facts = setup(text)
    rec, = facts["react_async"]["records"]
    assert rec["controls"][0]["truthy_disabled_states"] == []
    assert network_cleanup_identity(raw(rec), facts) is None
    text = text.replace("!saved.trim() || saving", "saving || !saved.trim()")
    _, _, facts = setup(text)
    rec, = facts["react_async"]["records"]
    assert network_cleanup_identity(raw(rec), facts)


def test_identity_projection_metadata_cannot_change_model_prompt():
    from app.scan.source_facts import facts_prompt
    _, _, facts, rec = scene()
    assert rec["network_projection_context"]
    before = deepcopy(facts)
    prompt = facts_prompt(facts)
    assert facts == before
    assert all(key not in prompt for key in ("network_projection_context", "response_json_calls", "visible_states",
                                             "truthy_disabled_states", "network_cleanup_bindings", "source_sha256"))
