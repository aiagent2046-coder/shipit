"""Paired HTTP-result/UI regressions; uploaded code is parsed, never executed."""
import io
import json
import zipfile

import pytest

from app.scan.http_success import RULE_ID, http_success_findings
from app.scan.react_async_context import collect_react_async_context


def component(body, *, extra="", label="Saved", jsx=None):
    return """import {useState} from 'react';
import {useRouter} from 'next/navigation';
export function Page() {
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const router = useRouter();
""" + extra + "\nconst save = async () => {\n" + body + "\n};\nreturn " + (
        jsx or "<button onClick={save}>{saving ? 'Saving' : saved ? '" + label + "' : 'Save'}</button>"
    ) + ";\n}\n"


def scan(source, path="src/Page.tsx"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(path, source)
    return {"react_async": collect_react_async_context(buf)}


def findings(body, **kwargs):
    return http_success_findings(scan(component(body, **kwargs)))


@pytest.mark.parametrize("prefix,suffix", [("", ""), ("try {", "} catch(e) { setSaving(false); }"),
                                          ("try {", "} finally { setSaving(false); }")])
@pytest.mark.parametrize("fetch_stmt", ["await fetch('/save');", "const response = await fetch('/save');"])
def test_resolved_http_failure_can_reach_visible_success_despite_catch_or_finally(prefix, suffix, fetch_stmt):
    result, = findings("setSaving(true); setSaved(false);\n" + prefix + fetch_stmt +
                       "\nsetSaving(false); setSaved(true);" + suffix, label="✓ Сохранено")
    assert result.rule_id == RULE_ID and result.category == "Frontend"
    assert result.severity == "medium" and result.source == "static"
    assert result.verification_status == "unverified" and result.verification_method == "source_pattern"
    check, = result.claim_evidence["context_checks"]
    assert check["effect"] == "success_state" and check["fetch_line"] < check["effect_line"]
    assert "HTTP 4xx/5xx" in result.explanation and "rejected request" in result.explanation
    assert result.claim_evidence["conditions_status"] == "not_checked"
    assert result.claim_evidence["consequence_status"] == "not_checked"


@pytest.mark.parametrize("body", [
    "const r = await fetch('/save'); if (!r.ok) return; setSaved(true);",
    "const r = await fetch('/save'); if (!r.ok) throw new Error('failed'); setSaved(true);",
    "const r = await fetch('/save'); if (r.ok) setSaved(true);",
    "const r = await fetch('/save'); if (r.status !== 201) return; setSaved(true);",
    "const r = await fetch('/save'); requireSuccess(r); setSaved(true);",
    "const r = await fetch('/save'); const data = await r.json(); if (data.error) return; setSaved(true);",
    "const r = await fetch('/save'); await r.json(); setSaved(true);",
    "await saveViaWrapper(); setSaved(true);",
    "await fetch('/save').then(requireSuccess); setSaved(true);",
    "const {ok} = await fetch('/save'); if(!ok) return; setSaved(true);",
])
def test_status_aware_or_indirect_response_handling_is_not_flagged(body):
    assert not findings(body)


def test_real_bigfive_shape_catches_rejection_but_still_navigates_after_http_error():
    result, = findings("""setSaving(true);
try {
  const token = await getAuthToken();
  await fetch('/save', {method: 'POST', headers: {Authorization: token}});
  try { telemetry.capture('completed', {value: scores.value}); } catch {}
  router.push('/next');
} catch { setSaving(false); }""")
    check, = result.claim_evidence["context_checks"]
    assert check["effect"] == "navigation" and "Navigation" in result.title
    safe = """try {
const r = await fetch('/save');
if (!r.ok) throw new Error('failed');
try { telemetry.capture('completed'); } catch {}
router.push('/next');
} catch { setSaving(false); }"""
    assert not findings(safe)


@pytest.mark.parametrize("method", ["push", "replace"])
def test_imported_next_router_alias_is_resolved(method):
    source = component("await fetch('/save'); router." + method + "('/next');")
    source = source.replace("{useRouter}", "{useRouter as useNavigation}").replace("useRouter()", "useNavigation()")
    assert http_success_findings(scan(source))[0].claim_evidence["context_checks"][0]["effect"] == "navigation"


@pytest.mark.parametrize("change", [
    lambda s: s.replace("'next/navigation'", "'custom-router'"),
    lambda s: s.replace("{useRouter}", "type {useRouter}"),
    lambda s: s.replace("const router = useRouter();", "const router = createRouter();"),
    lambda s: s.replace("await fetch", "router = custom; await fetch"),
    lambda s: s.replace("await fetch", "router.push = custom; await fetch"),
    lambda s: s.replace("const save", "function other(router) {}\nconst save"),
    lambda s: s.replace("const save", "const alias = router; alias.push = () => {};\nconst save"),
    lambda s: s.replace("const save", "Object.assign(router, {push: () => {}});\nconst save"),
    lambda s: s.replace("const save", "const escaped = {router}; mutate(escaped);\nconst save"),
    lambda s: s.replace("router.push('/next')", "router?.push('/next')"),
    lambda s: s.replace("router.push('/next')", "router.push?.('/next')"),
])
def test_custom_shadowed_reassigned_optional_router_is_unresolved(change):
    assert not http_success_findings(scan(change(component("await fetch('/save'); router.push('/next');"))))


@pytest.mark.parametrize("extra", [
    "const fetch = request;", "function fetch() {}", "fetch = request;",
    "function wrapper(fetch) {}", "globalThis.fetch = request;", "window.fetch = request;",
    "self['fetch'] = request;", "window['fe' + 'tch'] = request;",
    "Object.defineProperty(globalThis, 'fetch', {value: request});",
    "const globalAlias = window; globalAlias.fetch = request;",
])
def test_fetch_shadowing_and_local_global_replacements_are_not_assumed_standard(extra):
    assert not findings("await fetch('/save'); setSaved(true);", extra=extra)


@pytest.mark.parametrize("body", [
    "return; await fetch('/save'); setSaved(true);",
    "return; try { await fetch('/save'); setSaved(true); } catch {}",
    "if(false) { try { await fetch('/save'); setSaved(true); } catch {} }",
    "if (ready) { await fetch('/save'); setSaved(true); }",
    "while (ready) { await fetch('/save'); setSaved(true); }",
    "try { failure(); } catch(e) { await fetch('/save'); setSaved(true); }",
    "try { failure(); } finally { await fetch('/save'); setSaved(true); }",
    "await fetch('/save'); if(ready) setSaved(true);",
    "await fetch('/save'); await another(); setSaved(true);",
    "await fetch('/save'); unknown(); setSaved(true);",
    "await fetch('/save'); try { unknown(); } catch(e) { throw e; } setSaved(true);",
    "await fetch('/save'); try { await unknown(); } catch {} setSaved(true);",
    "await fetch('/save'); try { unknown(); } catch {} finally { return; } setSaved(true);",
    "await fetch('/save'); try { unknown(() => setSaved(true)); } catch {} router.push('/next');",
    "let r = await fetch('/save'); r = another; setSaved(true);",
    "const r = await fetch('/save'), ok = check(r); setSaved(true);",
])
def test_opaque_flow_or_response_binding_is_left_unknown(body):
    assert not findings(body)


@pytest.mark.parametrize("jsx", [
    "<button onClick={save}>Save</button>",
    "<button onClick={save} title={saved ? 'Saved' : 'Save'}>Save</button>",
    "<button onClick={save}>{!saved ? 'Saved' : 'Save'}</button>",
    "<button onClick={save}>{saved ? 'Failed' : 'Save'}</button>",
    "<button onClick={save}>{saved ? label : 'Save'}</button>",
    "<button onClick={save}>{false ? saved ? 'Saved' : 'Save' : 'Never saved'}</button>",
])
def test_arbitrary_true_setter_or_nonvisible_label_is_not_a_success_observation(jsx):
    assert not findings("await fetch('/save'); setSaved(true);", jsx=jsx)


def test_plain_fetch_and_loading_reset_are_not_findings():
    assert not findings("await fetch('/save'); setSaving(false);")


@pytest.mark.parametrize("body", [
    "setSaving(true); await fetch('/save'); setSaved(true);",
    "setSaving(unknown); await fetch('/save'); setSaved(true);",
    "setSaving(() => true); await fetch('/save'); setSaved(true);",
    "setSaving?.(true); await fetch('/save'); setSaved(true);",
    "if (ready) setSaving(true); await fetch('/save'); setSaved(true);",
    "setSaving(true); try { await fetch('/save'); setSaved(true); } catch {}",
    "await fetch('/save'); setSaved(true); setSaving(true);",
    "await fetch('/save'); setSaved(true); setSaving(() => true);",
])
def test_loading_branch_that_masks_saved_label_is_not_a_visible_success(body):
    assert not findings(body)


def test_explicit_loading_reset_allows_the_nested_success_label():
    assert findings("setSaving(true); await fetch('/save'); setSaving(false); setSaved(true);")
    assert findings("setSaving(true); try { await fetch('/save'); setSaving(false); setSaved(true); } catch {}")


@pytest.mark.parametrize("wrapper", [
    "<div hidden>{saved ? 'Saved' : 'Save'}</div>",
    "<div hidden={true}><p>{saved ? 'Saved' : 'Save'}</p></div>",
    "<div hidden={unknown}>{saved ? 'Saved' : 'Save'}</div>",
    "<div aria-hidden='true'>{saved ? 'Saved' : 'Save'}</div>",
    "<div {...props}>{saved ? 'Saved' : 'Save'}</div>",
    "<div style={{display: 'none'}}>{saved ? 'Saved' : 'Save'}</div>",
    "<div style={{visibility: 'hidden'}}>{saved ? 'Saved' : 'Save'}</div>",
    "<HiddenWrapper>{saved ? 'Saved' : 'Save'}</HiddenWrapper>",
])
def test_hidden_or_unknown_ancestor_does_not_establish_visible_success(wrapper):
    assert not findings("await fetch('/save'); setSaved(true);", jsx=wrapper)


def test_explicit_false_hidden_attribute_does_not_mask_success():
    assert findings("await fetch('/save'); setSaved(true);", jsx="<div hidden={false}>{saved ? 'Saved' : 'Save'}</div>")


@pytest.mark.parametrize("later", [
    "setSaved(() => false);", "setSaved(unknown);", "setSaved(v => !v);",
    "setSaved?.(() => false);",
    "if (ready) setSaved(false);", "try { other(); } finally { setSaved(() => false); }",
    "try { setSaved(false); } catch {}",
])
def test_later_unknown_or_functional_state_write_prevents_visible_success_claim(later):
    assert not findings("await fetch('/save'); setSaved(true); " + later)


def test_deferred_success_reset_still_allows_the_observed_success_state():
    assert findings("await fetch('/save'); setSaved(true); setTimeout(() => setSaved(false), 2000);")


@pytest.mark.parametrize("jsx", [
    "<div>{saved && <p>Saved</p>}</div>",
    "<div>{saved ? <p>✓ Сохранено</p> : null}</div>",
])
def test_simple_native_success_text_can_be_a_conditional_child(jsx):
    assert len(findings("await fetch('/save'); setSaved(true);", jsx=jsx)) == 1


@pytest.mark.parametrize("jsx", [
    "<div>{saved && <Message>Saved</Message>}</div>",
    "<div>{saved && <p hidden>Saved</p>}</div>",
    "<div>{saved && <p>{label}</p>}</div>",
    "<div>{saved && <p>Not saved</p>}</div>",
])
def test_custom_hidden_dynamic_or_negative_label_is_not_a_supported_success(jsx):
    assert not findings("await fetch('/save'); setSaved(true);", jsx=jsx)


@pytest.mark.parametrize("body", [
    "await fetch('/save'); setSaved(true); setSaved(false);",
    "await fetch('/save');setSaved(true);setSaved(false);",
    "try { await fetch('/save'); setSaved(true); } finally { setSaved(false); }",
    "await fetch?.('/save'); setSaved(true);",
    "await fetch('/save'); setSaved?.(true);",
    "await fetch(); setSaved(true);",
])
def test_synchronously_reverted_optional_or_invalid_effect_is_unknown(body):
    assert not findings(body)


def test_initially_true_or_unknown_success_state_is_not_assumed_to_transition():
    source = component("await fetch('/save'); setSaved(true);")
    for initial in ("true", "unknown", "'false'"):
        assert not http_success_findings(scan(source.replace("[saved, setSaved] = useState(false)",
                                                             "[saved, setSaved] = useState(" + initial + ")")))


def test_unused_jsx_variable_or_conditional_return_is_not_assumed_visible():
    source = component("await fetch('/save'); setSaved(true);")
    assert not http_success_findings(scan(source.replace("return <button", "const unused = <button")))
    assert not http_success_findings(scan(source.replace("return <button", "if (false) return <button")))


def test_literals_comments_and_credentials_never_enter_facts_or_findings():
    body = """// await fetch('/other'); setSaved(true);
const text = "await fetch('/other'); setSaved(true); secret-literal";
await fetch('/secret-url', {headers: {Authorization: 'secret-token'}});
router.push('/secret-destination');"""
    facts = scan(component(body))
    result, = http_success_findings(facts)
    encoded = json.dumps([facts, vars(result)])
    assert not any(value in encoded for value in ["secret-url", "secret-token", "secret-destination", "secret-literal"])


def test_comments_do_not_create_success_effect_and_duplicate_observations_do_not_duplicate_findings():
    assert not findings("await fetch('/save'); /* setSaved(true); */")
    facts = scan(component("await fetch('/save'); setSaved(true);"))
    before = json.dumps(facts, sort_keys=True)
    assert len(http_success_findings(facts)) == 1
    assert json.dumps(facts, sort_keys=True) == before
    facts["react_async"]["records"] *= 2
    assert len(http_success_findings(facts)) == 1


def test_excluded_and_unparseable_source_does_not_create_static_findings():
    source = component("await fetch('/save'); setSaved(true);")
    for path in ["tests/Page.tsx", "vendor/Page.tsx", "node_modules/Page.tsx"]:
        assert not http_success_findings(scan(source, path))
    assert not http_success_findings(scan("export function Page( {"))
