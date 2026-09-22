"""Boundaries of static literal resolution -- each test is a claim.

Following a statically knowable value is READING; following anything else is
guessing. These tests pin both halves: what must resolve (concatenations,
unambiguous chains) and what must stay UNRESOLVED (sibling scopes, use before
binding, rebound names, parameters, f-strings, runaway chains).
"""

from __future__ import annotations

import ast

from app.scan.literal_values import UNRESOLVED, literal_context


def resolve(source: str, expression: str) -> object:
    tree = ast.parse(source)
    context = literal_context(tree)
    call = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "use"
    )
    assert len(call.args) == 1
    return context.resolve(call.args[0])


def test_concatenation_of_literals_is_a_literal():
    assert resolve('use("a" + "b")', "a") == "ab"


def test_chain_of_unambiguous_bindings_resolves():
    assert resolve('a = "x"\nb = a\nuse(b)', "b") == "x"


def test_sibling_scope_binding_is_not_evidence():
    source = "def f():\n    use(flag)\n\ndef g():\n    flag = 1\n"
    assert resolve(source, "flag") is UNRESOLVED


def test_use_before_binding_is_not_evidence():
    assert resolve("use(flag)\nflag = 1\n", "flag") is UNRESOLVED


def test_rebound_name_is_not_evidence():
    assert resolve('a = "x"\na = "y"\nuse(a)', "a") is UNRESOLVED


def test_parameter_is_not_evidence():
    source = "def f(flag):\n    use(flag)\n"
    assert resolve(source, "flag") is UNRESOLVED


def test_fstring_stays_unresolved():
    assert resolve('name = "x"\nuse(f"{name}=1")', "f") is UNRESOLVED


def test_a_chain_that_never_ends_resolves_to_unresolved():
    assert resolve("a = b\nb = a\nuse(a)", "a") is UNRESOLVED


def test_none_value_is_a_value_not_an_absence():
    assert resolve("mode = None\nuse(mode)", "mode") is None
