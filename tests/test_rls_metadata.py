"""Regression cases learned from a public table with an unintended ALL policy."""
from __future__ import annotations

import copy
import json

import pytest

from app.proof.rls_metadata import MetadataInputError, parse_access_review, review_metadata
from app.proof.types import ExploitAttempt

REF = "abcdefghijklmnopqrst"


def policy(name="all", command="ALL", using="always", check=None, permissive=True, roles=None):
    return {"name": name, "command": command, "permissive": permissive,
            "applies_to": roles if roles is not None else ["anon", "authenticated"],
            "using": using, "with_check": check}


def metadata():
    return {
        "snapshot": {
            "version": 1, "project_ref": REF, "captured_at": "2026-09-11T12:00:00Z",
            "collector_role": "postgres", "schema_name": "public", "tables": [{
                "name": "shared_stacks", "object_type": "r", "rls_enabled": True,
                "rls_forced": False, "collector_rls_applies": False, "row_count": 2,
                "columns": [{"name": "is_public", "type": "boolean", "nullable": True}],
                "privileges": [{"role": role, "schema_usage": True, "rls_bypassed": False,
                                **{key: True for key in ("select", "select_any_column", "insert", "insert_any_column",
                                                        "update", "update_any_column", "delete")}}
                               for role in ("anon", "authenticated")],
                "policies": [policy("published", "SELECT", "conditional"), policy()],
            }],
        },
        "auth_model": "backend",
        "expectations": [{"table": "shared_stacks", "read": "public_subset", "write": "backend_only"}],
    }


def analyze(data, reason="rows_readable"):
    attempt = ExploitAttempt(template_id="rls_open_runtime", success=reason == "rows_readable",
                             status="success" if reason == "rows_readable" else "failure", detail="",
                             evidence={"table": "shared_stacks", "reason": reason})
    return review_metadata(parse_access_review(json.dumps(data)), [attempt])


def ops(data, **kwargs):
    return analyze(data, **kwargs)["tables"][0]["operations"]


def test_public_read_does_not_hide_unrestricted_writes_or_filter_override():
    data = metadata()
    report = analyze(data)
    assert all(o["scope"] == "unrestricted" and o["assessment"] == "mismatch" for o in ops(data))
    assert report["tables"][0]["interpretation"] == "public_subset_unverified"
    data["expectations"][0]["read"] = "public"
    result = analyze(data)["tables"][0]
    assert result["interpretation"] == "expected_public_read"
    assert all(o["assessment"] == "mismatch" for o in result["operations"] if o["operation"] != "SELECT")


def test_removing_all_policy_keeps_public_reads_and_denies_writes_with_grants_intact():
    data = metadata()
    data["snapshot"]["tables"][0]["policies"].pop()
    for o in ops(data):
        assert o["scope"] == ("conditional" if o["operation"] == "SELECT" else "blocked")
        assert o["assessment"] == ("review_needed" if o["operation"] == "SELECT" else "consistent")


@pytest.mark.parametrize("pred,expected", [("always", "unrestricted"), ("never", "blocked"),
                                           ("conditional", "conditional")])
def test_restrictive_policies_combine_with_and(pred, expected):
    data = metadata()
    data["snapshot"]["tables"][0]["policies"].append(policy("restriction", using=pred, permissive=False))
    assert {o["scope"] for o in ops(data)} == {expected}


def test_restrictive_only_does_not_grant_access():
    data = metadata()
    data["snapshot"]["tables"][0]["policies"] = [policy(permissive=False)]
    assert {o["scope"] for o in ops(data)} == {"blocked"}


@pytest.mark.parametrize("check,scope", [(None, "unrestricted"), ("never", "blocked"),
                                      ("conditional", "conditional")])
def test_with_check_inherits_using_only_when_absent(check, scope):
    data = metadata()
    data["snapshot"]["tables"][0]["policies"] = [policy(check=check)]
    for o in ops(data):
        assert o["scope"] == (scope if o["operation"] in {"INSERT", "UPDATE"} else "unrestricted")


def test_role_and_command_scope_and_owner_visibility_are_separate():
    data = metadata()
    data["snapshot"]["tables"][0]["policies"] = [policy(command="SELECT", roles=["authenticated"])]
    assert [(o["role"], o["operation"]) for o in ops(data) if o["scope"] != "blocked"] == [
        ("authenticated", "SELECT")]
    result = analyze(data, reason="empty_result")["tables"][0]
    assert result["row_count"] == 2
    assert result["observation"] == "empty_result"
    assert result["interpretation"] == "no_read_conclusion"
    assert not result["collector_rls_applies"]


@pytest.mark.parametrize("key", ["rls_bypassed", "rls_disabled"])
def test_bypass_or_disabled_rls_ignores_policies_but_still_needs_grants(key):
    data = metadata()
    table = data["snapshot"]["tables"][0]
    table["policies"] = []
    if key == "rls_disabled":
        table["rls_enabled"] = False
    else:
        for role in table["privileges"]:
            role["rls_bypassed"] = True
    assert {o["reason"] for o in ops(data)} == {key}
    for role in table["privileges"]:
        role["update"] = role["update_any_column"] = False
    assert {o["scope"] for o in ops(data) if o["operation"] == "UPDATE"} == {"blocked"}


def test_column_grants_and_schema_usage_are_not_lost():
    data = metadata()
    table = data["snapshot"]["tables"][0]
    table["privileges"][0]["update"] = False
    update = next(o for o in ops(data) if o["role"] == "anon" and o["operation"] == "UPDATE")
    assert update["scope"] == "unrestricted" and update["column_limited"]
    table["privileges"][0]["schema_usage"] = False
    assert all(o["scope"] == "blocked" for o in ops(data) if o["role"] == "anon")


@pytest.mark.parametrize("kind", ["v", "m", "f"])
def test_other_relations_are_not_treated_as_rls_tables(kind):
    data = metadata()
    data["snapshot"]["tables"][0]["object_type"] = kind
    assert {o["scope"] for o in ops(data)} == {"unknown"}


def test_live_read_conflict_is_reported_not_overridden_by_a_snapshot():
    data = metadata()
    data["snapshot"]["tables"][0]["policies"] = []
    result = analyze(data)["tables"][0]
    assert result["evidence_conflict"]
    assert result["observation"] == "rows_readable"


def test_digest_and_unchecked_tables_and_unknown_expectations():
    data = metadata()
    data["expectations"] = []
    parsed = parse_access_review(json.dumps(data))
    result = review_metadata(parsed, [])
    assert len(result["snapshot_sha256"]) == 64
    assert result["source"] == "owner_supplied_metadata"
    assert result["tables"][0]["observation"] == "not_checked"
    assert {o["assessment"] for o in result["tables"][0]["operations"]} == {"expectation_missing"}


@pytest.mark.parametrize("mutate", [
    lambda d: d["snapshot"].update(version=2),
    lambda d: d["snapshot"].update(version=True),
    lambda d: d["snapshot"].update(version=1.0),
    lambda d: d["snapshot"].update(project_ref="http://127.0.0.1"),
    lambda d: d["snapshot"].update(captured_at="2026-09-11"),
    lambda d: d["snapshot"].update(schema_name="private"),
    lambda d: d["snapshot"].update(tables=d["snapshot"]["tables"] * 101),
    lambda d: d["snapshot"]["tables"][0].update(rls_enabled="false"),
    lambda d: d["snapshot"]["tables"][0].update(privileges=[]),
    lambda d: d["snapshot"]["tables"][0].update(row_count=-1),
    lambda d: d["snapshot"]["tables"][0]["policies"][0].update(using="is_public = true"),
    lambda d: d["snapshot"]["tables"][0]["policies"][0].update(using="secret-input"),
    lambda d: d["snapshot"]["tables"][0]["policies"][0].update(applies_to=["anon", "anon"]),
    lambda d: d["expectations"].append(copy.deepcopy(d["expectations"][0])),
    lambda d: d["expectations"][0].update(table="another_table"),
    lambda d: d.update(service_role_key="secret-input"),
])
def test_invalid_snapshots_are_rejected_without_echoing_input(mutate):
    data = metadata()
    mutate(data)
    with pytest.raises(MetadataInputError) as error:
        parse_access_review(json.dumps(data))
    assert "secret-input" not in str(error.value)


@pytest.mark.parametrize("raw", ['{"snapshot":null,"snapshot":{}}', "[" * 1500, "x" * (256 * 1024 + 1)])
def test_bounded_strict_json(raw):
    with pytest.raises(MetadataInputError):
        parse_access_review(raw)
