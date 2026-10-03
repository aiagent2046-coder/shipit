"""Regression proof: literal dictionaries never blanket-suppress mutable input."""
import pytest

from app.scan.xss import _nodes, _parser
from app.scan.xss_literal_loop import build_literal_loop_bindings, literal_loop_binding


def proved(source, target="title"):
    nodes = _nodes(_parser(False).parse(source.encode()).root_node)
    facts = build_literal_loop_bindings(nodes)
    assignment = next(n for n in nodes if n.type == "assignment_expression" and
                      n.child_by_field_name("left").text == b"box.innerHTML")
    value = next(n for n in nodes if n.type == "identifier" and n.text.decode() == target and
                 assignment.start_byte <= n.start_byte < assignment.end_byte)
    return literal_loop_binding(value, assignment, facts)


BASE = '''const LABELS = { first: ["Title", "red"], second: ["Other", "blue"] };
function render() { for (const [key, [title, cls]] of Object.entries(LABELS)) {
  box.innerHTML = title + cls;
} }'''


def test_nested_literal_loop_matches_scout_shape():
    assert proved(BASE)
    assert proved(BASE, "cls")


def test_direct_string_values():
    assert proved('const LABELS={a:"text",b:"other"}; '
                  'for(const [key,title] of Object.entries(LABELS)){box.innerHTML=title;}')


@pytest.mark.parametrize("change", [
    lambda s: s.replace('"Other"', 'input'),
    lambda s: s.replace('second: ["Other", "blue"]', 'get second() {return input;}'),
    lambda s: s.replace('second: ["Other", "blue"]', '...input'),
    lambda s: s.replace('"Other", "blue"', '"Other"'),
    lambda s: s.replace('"Title", "red"', ', "red"'),
    lambda s: s.replace('"Title", "red"', '...input'),
    lambda s: s.replace('function render()', 'LABELS.first[0] = input; function render()'),
    lambda s: s.replace('function render()', 'consume(LABELS); function render()'),
    lambda s: s.replace('function render()', 'const alias = LABELS; function render()'),
    lambda s: s.replace('function render()', 'function render(LABELS)'),
    lambda s: s.replace('function render()', 'function render(Object)'),
    lambda s: s.replace('function render()', 'Object.entries = custom; function render()'),
    lambda s: s.replace('function render()', 'const O = Object; function render()'),
    lambda s: s.replace('function render()', 'globalThis.Object = custom; function render()'),
    lambda s: s.replace('function render()', 'globalThis["Object"].entries = custom; function render()'),
    lambda s: s.replace('function render()', 'const globals = window; function render()'),
    lambda s: s.replace('function render()', 'function render(title)'),
    lambda s: s.replace('box.innerHTML', 'title = input; box.innerHTML'),
    lambda s: s.replace('box.innerHTML', 'title++; box.innerHTML'),
    lambda s: s.replace('box.innerHTML', '({title} = input); box.innerHTML'),
    lambda s: s.replace('box.innerHTML', 'const title = input; box.innerHTML'),
    lambda s: s.replace('box.innerHTML', 'class title {} box.innerHTML'),
    lambda s: s.replace('box.innerHTML = title + cls;', 'function closure(){box.innerHTML = title + cls;}'),
    lambda s: s + '\nfunction unrelated(title) {}',
    lambda s: s + '\neval(code);',
    lambda s: s + '\nconst factory = Function;',
    lambda s: s.replace('const LABELS', 'export const LABELS'),
    lambda s: s.replace('const LABELS', 'let LABELS'),
    lambda s: s.replace('const [key', 'let [key'),
    lambda s: s.replace('[title, cls]', '[title = input, cls]'),
    lambda s: s.replace('[title, cls]', '[title, title]'),
    lambda s: s.replace('[title, cls]', '[...title]'),
    lambda s: s.replace('Object.entries(LABELS)', 'Object.entries?.(LABELS)'),
    lambda s: s.replace('Object.entries(LABELS)', 'Object["entries"](LABELS)'),
    lambda s: s.replace('const LABELS', 'const L\\u0041BELS'),
])
def test_unproven_cases_remain_visible(change):
    # Test the cls missing-value mutation separately; title still exists there.
    source = change(BASE)
    if 'second: ["Other"]' in source:
        assert not proved(source, "cls")
    else:
        assert not proved(source)


def test_different_loop_does_not_inherit_binding():
    source = BASE + '\nfor(const title of input){box.innerHTML=title;}'
    assert not proved(source)


def test_outside_reference_prevents_proof():
    assert not proved(BASE + '\nconsume(title);')


def test_fixed_string_can_be_read_by_a_call():
    assert proved(BASE.replace('box.innerHTML', 'consume(title); box.innerHTML'))


def test_unrelated_property_name_does_not_shadow_binding():
    assert proved(BASE.replace('box.innerHTML', 'object.title = input; box.innerHTML'))


def test_input_limits_abstain():
    nodes = _nodes(_parser(False).parse(BASE.encode()).root_node)
    assert build_literal_loop_bindings(nodes * 1000) == set()
