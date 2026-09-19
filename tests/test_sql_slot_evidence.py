"""SQL slot evidence must describe the template, never an invented query."""

from __future__ import annotations

import builtins
import json

import pytest

from app.scan.sql_slot_evidence import classify_sql_slots


def classify(parts):
    return classify_sql_slots(parts, spend=lambda count: None)


@pytest.mark.parametrize("parts,slots", [
    (["SELECT * FROM users WHERE id = ", 0], [0]),
    (["SELECT users.id FROM public.users WHERE users.id = ", 0], [0]),
    (["SELECT id FROM users WHERE name = '", 0, "'"], [0]),
    (["SELECT id FROM users WHERE name = 'prefix-", 0, "-suffix'"], [0]),
    (["SELECT id FROM users WHERE name = '", 0, "/", 1, "'"], [0, 1]),
    (["SELECT id FROM users WHERE name = '", 0, "' AND id = ", 1], [0, 1]),
    (["SELECT id FROM users WHERE id = ", 0, " OR (id = ", 0, ")"], [0]),
    (["SELECT id FROM users WHERE id = ", 0, " AND status = 1;"], [0]),
    (["SELECT id FROM users WHERE name = 'it'", "'s-", 0, "'"], [0]),
    (["SELECT id FROM users WHERE name = '--/*$", 0, "$*/'"], [0]),
    (['SELECT "id" FROM "users" WHERE "users"."id" = ', 0], [0]),
])
def test_establishes_only_unambiguous_where_value_slots(parts, slots):
    assert classify(parts) == {
        "status": "established",
        "reason": "sql_value_positions_established",
        "facts": [{
            "id": "sql_value_position",
            "method": "postgresql_ast_slot_context",
            "slots": [{"index": index, "role": "value"} for index in slots],
        }],
    }


@pytest.mark.parametrize("parts", [
    ["SELECT ", 0, " FROM users"],
    ["SELECT ", 0, " FROM users WHERE id = ", 1],
    ["SELECT id FROM users ORDER BY ", 0],
    ["SELECT id FROM users WHERE id = 1 ORDER BY ", 0],
    ["SELECT id FROM ", 0],
    ['SELECT id FROM "', 0, '" WHERE id = 1'],
    ['SELECT id FROM users WHERE "', 0, '" = 1'],
    ["SELECT id FROM users WHERE ", 0, " = id"],
    ["SELECT id FROM users WHERE id = ", 0, " + 1"],
    ["SELECT id FROM users WHERE id = ", 0, "::int"],
    ["SELECT id FROM users WHERE id = COALESCE(", 0, ", 1)"],
    ["SELECT id FROM users WHERE id IN (", 0, ")"],
    ["SELECT id FROM users WHERE id = ", 0, " LIMIT ", 1],
    ["SELECT id FROM users WHERE id = ", 0, "; SELECT 1"],
    ["UPDATE users SET id = ", 0],
    ["SELECT id FROM users WHERE id = ", 0, " UNION SELECT 1"],
    ["SELECT * FROM (SELECT id FROM users WHERE id = ", 0, ") AS ids"],
    ["SELECT id FROM users WHERE id = 1", 0],
    ["SELECT id FROM users WHERE id = ", 0, "abc"],
])
def test_does_not_turn_parseable_parameters_into_role_evidence(parts):
    result = classify(parts)
    assert result["status"] in ("unknown", "unsupported")
    assert result["facts"] == []


@pytest.mark.parametrize("parts", [
    ["SELECT id FROM users WHERE name = E'", 0, "'"],
    ["SELECT id FROM users WHERE name = ", "E", "'", 0, "'"],
    ["SELECT id FROM users WHERE name = B'", 0, "'"],
    ["SELECT id FROM users WHERE name = X'", 0, "'"],
    ["SELECT id FROM users WHERE name = N'", 0, "'"],
    ["SELECT id FROM users WHERE name = U&'", 0, "'"],
    ["SELECT id FROM users WHERE name = $$", 0, "$$"],
    ["SELECT id FROM users WHERE name = $body$", 0, "$body$"],
    ["SELECT id FROM users WHERE name = 'prefix\\", 0, "'"],
    ["SELECT id FROM users WHERE name = '", 0, "'\n'joined'"],
    ["SELECT id FROM users WHERE name = 'fixed'\n'", 0, "'"],
    ["SELECT id FROM users WHERE name = '", 0, "'-- ignored"],
    ["SELECT id FROM users WHERE name = '", 0, "'-", "- ignored"],
    ["SELECT id FROM users /", "* WHERE id = ", 0, " */"],
    ["SELECT id FROM users -- WHERE id = ", 0],
    ["SELECT id FROM users WHERE name = 'unclosed", 0],
    ["SELECT id FROM users WHERE name = 'closed'", 0, "'reopened'"],
    ["SELECT id FROM users WHERE id = ", 0, "\x00"],
])
def test_lexical_boundaries_cannot_manufacture_value_evidence(parts):
    result = classify(parts)
    assert result["status"] in ("unknown", "unsupported")
    assert result["facts"] == []


def test_every_occurrence_must_have_a_supported_role_even_for_repeated_index():
    assert classify(["SELECT ", 0, " FROM users WHERE id = ", 0])["facts"] == []


def test_evidence_does_not_contain_sql_or_literal_values():
    parts = ["SELECT private_name FROM customer_secrets WHERE key = 'secret-", 0, "'"]
    rendered = json.dumps(classify(parts))
    assert "customer_secrets" not in rendered
    assert "private_name" not in rendered
    assert "secret-" not in rendered


def test_missing_parser_preserves_unknown_evidence(monkeypatch):
    original = builtins.__import__

    def without_parser(name, *args, **kwargs):
        if name == "pglast":
            raise ImportError("native parser unavailable")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_parser)
    assert classify(["SELECT id FROM users WHERE id = ", 0]) == {
        "status": "unsupported", "reason": "sql_parser_unavailable", "facts": [],
    }


@pytest.mark.parametrize("parts", [
    ["SELECT id FROM users WHERE id = ", True],
    ["SELECT id FROM users WHERE id = ", -1],
    ["SELECT id FROM users WHERE id = ", 64],
    ["SELECT id FROM users WHERE id = ", 1],
    ["SELECT id FROM users WHERE id = ", None],
    ["SELECT id FROM users WHERE id = ", {"index": 0}],
])
def test_invalid_symbolic_slots_never_establish_evidence(parts):
    assert classify(parts)["facts"] == []


def test_limits_are_fail_closed_without_discarding_budget_exhaustion():
    for parts in ([" " * 16_385, 0], ["😀" * 5_000, 0], [0] * 65, [""] * 257):
        assert classify(parts) == {
            "status": "unsupported", "reason": "sql_input_limit", "facts": [],
        }

    class Exhausted(Exception):
        pass

    budget = 70

    def spend(amount):
        nonlocal budget
        budget -= amount
        if budget < 0:
            raise Exhausted

    with pytest.raises(Exhausted):
        classify_sql_slots(["SELECT * FROM users WHERE id = ", 0], spend=spend)


def test_no_dynamic_input_cannot_prove_a_slot_role():
    assert classify(["SELECT id FROM users WHERE id = 1"]) == {
        "status": "unknown", "reason": "sql_slots_missing", "facts": [],
    }
