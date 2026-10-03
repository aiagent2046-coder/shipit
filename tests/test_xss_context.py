"""Descriptive source facts must not imply sanitizer or runtime trust proofs."""
import json

import pytest

from app.scan.xss import _declarations, _nodes, _parser, _sink
from app.scan.xss_context import describe_html_inputs


def describe(source):
    root = _parser(False).parse(source.encode()).root_node
    assert not root.has_error
    nodes = _nodes(root)
    sink, value = next((n, _sink(n)[1]) for n in nodes if _sink(n)[0])
    return describe_html_inputs(value, sink, nodes, _declarations(nodes))


def test_call_name_never_means_sanitized_and_arguments_are_not_disclosed():
    facts = describe('el.innerHTML = "<p>" + escapeHtml("private test value") + "</p>";')
    assert facts["calls"] == ["escapeHtml"]
    assert facts["parts"] == {"literal": 2, "calls_unverified": 1, "unresolved": 0, "literal_dictionary_bindings": 0}
    assert facts["status"] == "mixed"
    assert "private test value" not in json.dumps(facts)
    assert "sanitized" not in json.dumps(facts)


def test_template_and_parenthesized_concatenation():
    facts = describe('el.innerHTML = (`<p>${unknown}</p>` + ("<hr>"));')
    assert facts["parts"]["literal"] == 2
    assert facts["references"] == ["unknown"]


def test_one_hop_const_traces_branch_calls():
    facts = describe('const url = href ? "<a>" + escapeHtml(href) : ""; el.innerHTML = url;')
    assert facts["const_bindings_resolved"] == 1
    assert facts["calls"] == ["escapeHtml"]
    assert facts["parts"]["literal"] == 2


@pytest.mark.parametrize("source", [
    'const a = "<p>"; const b = a; el.innerHTML = b;',
    'const a = "<p>"; function render() { el.innerHTML = a; }',
    'el.innerHTML = a; const a = "<p>";',
    'let a = "<p>"; el.innerHTML = a;',
    'const a = "<p>"; a = outside; el.innerHTML = a;',
    'const a = "<p>"; function render(a) { el.innerHTML = a; }',
    '{ const a = "<p>"; } el.innerHTML = a;',
    'const a = "<p>"; { const a = external; el.innerHTML = a; }',
])
def test_ambiguous_or_transitive_bindings_stay_unresolved(source):
    facts = describe(source)
    assert facts["parts"]["unresolved"] == 1
    assert facts["parts"]["literal"] == 0


def test_dictionary_initializer_is_observation_only_across_function():
    facts = describe('const TAGS = {a: ["title", "cls"]}; function render() { '
                     'for (const [key, [title, cls]] of Object.entries(TAGS)) { '
                     'el.innerHTML = "<span>" + cls + title; } }')
    assert facts["parts"]["literal_dictionary_bindings"] == 2
    assert facts["status"] == "mixed"
    assert facts["references"] == ["cls", "title"]
    assert "safe" not in facts


@pytest.mark.parametrize("dictionary", [
    '{a: external}', '{...external}', '{[key]: ["x"]}', '{get a() { return "x"; }}',
])
def test_nonliteral_dictionary_is_unknown(dictionary):
    facts = describe(f'const TAGS = {dictionary}; '
                     'for (const [key, title] of Object.entries(TAGS)) { el.innerHTML = title; }')
    assert facts["parts"]["literal_dictionary_bindings"] == 0
    assert facts["parts"]["unresolved"] == 1


def test_loop_binding_does_not_escape_function_or_scope():
    facts = describe('const TAGS = {a: ["x"]}; for (const [key, title] of Object.entries(TAGS)) { '
                     'function delayed() { el.innerHTML = title; } }')
    assert facts["parts"]["literal_dictionary_bindings"] == 0


def test_unknown_member_and_dynamic_call_names_are_not_disclosed():
    facts = describe('el.innerHTML = record["private value"] + record["private call"]();')
    assert facts["parts"]["unresolved"] == 1
    assert facts["parts"]["calls_unverified"] == 1
    assert facts["calls"] == []
    assert "private" not in json.dumps(facts)


def test_method_call_is_unverified():
    facts = describe('el.innerHTML = new Date(d.createdAt).toLocaleString("ru-RU") + escapeHtml(d.profile);')
    assert facts["calls"] == ["toLocaleString", "escapeHtml"]
    assert facts["status"] == "calls"


def test_depth_budget_is_explicit():
    facts = describe('el.innerHTML = ' + '(' * 30 + '"x"' + ')' * 30 + ';')
    assert facts["limits"] is True
    assert facts["status"] == "unresolved"


def test_name_budget_and_length_bound():
    facts = describe('document.write(' + ','.join(f'fn{i}()' for i in range(20)) + ');')
    assert len(facts["calls"]) == 16
    assert facts["limits"] is True
    facts = describe('el.innerHTML = ' + 'a' * 100 + '();')
    assert facts["calls"] == []
    assert facts["parts"]["calls_unverified"] == 1


@pytest.mark.parametrize("prefix", ['const title = external;', 'title = external;'])
def test_loop_binding_rebinding_or_shadowing_abstains(prefix):
    facts = describe('const TAGS = {a: ["x"]}; for (const [key, title] of Object.entries(TAGS)) {'
                     + prefix + ' el.innerHTML = title; }')
    assert facts["parts"]["literal_dictionary_bindings"] == 0
    assert facts["parts"]["unresolved"] == 1
