"""Paired source fixtures for RLS-aware recommendations; never a live database."""
from io import BytesIO
import json
import zipfile

import pytest

from app.scan.rls_recommendations import collect_rls_recommendations, rls_recommendation_context


def archive(files):
    result = BytesIO()
    with zipfile.ZipFile(result, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    result.seek(0)
    return result


def collect(sql, operation="insert", table="agent_context", **files):
    return collect_rls_recommendations(archive({
        "app/api/context/route.ts": f"await supabase.from('{table}').{operation}({{}});",
        "supabase/migrations/0001_policies.sql": sql,
        **files,
    }))


def policy(command, table="public.agent_context", name="access"):
    tail = "WITH CHECK (auth.uid() = user_id)" if command == "INSERT" else "USING (auth.uid() = user_id)"
    return f"CREATE POLICY {name} ON {table} FOR {command} TO authenticated {tail};"


def recommendation(**changes):
    return {"file": "app/api/context/route.ts", "title": "Service-role client bypasses RLS",
            "fix_hint": "Switch to an anon-key client with the caller's JWT.", **changes}


@pytest.mark.parametrize("operation,needed", [("insert", ["INSERT"]), ("update", ["UPDATE"]),
                                              ("delete", ["DELETE"]), ("upsert", ["INSERT", "UPDATE"])])
def test_select_policy_is_not_a_write_policy(operation, needed):
    facts = collect(policy("SELECT"), operation)
    record = facts["records"][0]
    assert record["required_commands"] == needed
    assert record["commands_in_declared_sequence"] == ["SELECT"]
    assert record["missing_command_declarations"] == needed
    assert record["schema_basis"] == "conditional_default_public"
    context = rls_recommendation_context(recommendation(), {"rls_recommendations": facts})[0]
    assert context["result"] == "observed"
    assert "SELECT policies alone do not authorize writes" in context["summary"]
    assert "not applied database state" in context["detail"]


@pytest.mark.parametrize("command", ["INSERT", "UPDATE", "DELETE", "ALL"])
def test_corresponding_write_declaration_prevents_missing_command_claim(command):
    operation = "upsert" if command == "ALL" else command.lower()
    facts = collect(policy("SELECT", name="read") + policy(command), operation)
    assert facts["records"][0]["missing_command_declarations"] == []
    assert "do not prove access" in facts["scope"]


def test_upsert_requires_both_command_declarations():
    result = collect(policy("INSERT"), "upsert")["records"][0]
    assert result["missing_command_declarations"] == ["UPDATE"]


@pytest.mark.parametrize("other", ["public.other_table", "private.agent_context", 'public."Agent_Context"'])
def test_other_table_schema_or_identifier_case_does_not_cover_write(other):
    result = collect(policy("ALL", other))["records"][0]
    assert result["missing_command_declarations"] == ["INSERT"]
    assert result["policy_history"] == []


def test_exact_quoted_identifiers_and_explicit_schema():
    facts = collect_rls_recommendations(archive({
        "app/route.ts": "await db.schema('Private').from('Agent Context').delete();",
        "db/migrations/0001_policy.sql": policy("DELETE", '"Private"."Agent Context"', '"Own Records"'),
    }))
    result = facts["records"][0]
    assert result["schema"] == "Private"
    assert result["table"] == "Agent Context"
    assert result["schema_basis"] == "explicit_schema_call"
    assert result["missing_command_declarations"] == []
    assert result["policy_history"][0]["policy"] == "Own Records"


def test_drop_removes_same_named_policy_and_preserves_other_policies():
    facts = collect(policy("SELECT", name="read") + policy("INSERT", name="write"), **{
        "supabase/migrations/0002_drop.sql": "DROP POLICY IF EXISTS write ON public.agent_context;"})
    result = facts["records"][0]
    assert result["commands_in_declared_sequence"] == ["SELECT"]
    assert result["missing_command_declarations"] == ["INSERT"]
    assert [p["event"] for p in result["policy_history"]] == ["create", "create", "drop"]


def test_drop_then_create_restores_declaration_even_with_reverse_zip_order():
    files = {
        "supabase/migrations/0002_replace.sql": "DROP POLICY access ON public.agent_context;" + policy("DELETE"),
        "supabase/migrations/0001_initial.sql": policy("SELECT"),
        "app/route.ts": "await db.from('agent_context').delete();",
    }
    result = collect_rls_recommendations(archive(files))["records"][0]
    assert result["commands_in_declared_sequence"] == ["DELETE"]
    assert result["missing_command_declarations"] == []


def test_policy_references_skip_comments_and_preserve_unicode_line_positions():
    source = "-- комментарий\n\n" + policy("SELECT") + "\n-- Привет\nDROP POLICY access ON public.agent_context;"
    result = collect(source)["records"][0]
    assert [event["line"] for event in result["policy_history"]] == [3, 5]


def test_alter_keeps_original_command_and_records_role_change():
    result = collect(policy("SELECT") + "ALTER POLICY access ON public.agent_context TO anon USING(false);")
    record = result["records"][0]
    assert record["commands_in_declared_sequence"] == ["SELECT"]
    assert record["missing_command_declarations"] == ["INSERT"]
    assert record["policy_history"][-1]["event"] == "alter"
    assert record["policy_history"][-1]["roles"] == ["anon"]
    assert "USING(false)" not in json.dumps(record)


@pytest.mark.parametrize("extra,limitation", [
    ({"supabase/migrations/0002_bad.sql": "CREATE POLICY broken ON"}, "unparseable_migration_sql"),
    ({"supabase/migrations/0001_tie.sql": policy("ALL", name="other")}, "migration_order_ambiguous"),
    ({"db/migrations/0002_another_root.sql": policy("ALL", name="other")}, "migration_order_ambiguous"),
    ({"supabase/migrations/latest.sql": policy("ALL", name="other")}, "unnumbered_or_nested_migration"),
    ({"supabase/migrations/0002_alter.sql": "ALTER POLICY absent ON public.agent_context USING(true);"},
     "alter_without_observed_create"),
    ({"supabase/migrations/0002_do.sql": "DO $$ BEGIN CREATE POLICY hidden ON public.agent_context "
      "FOR ALL USING(true); END; $$;"}, "procedural_sql_not_resolved"),
    ({"supabase/migrations/0002_drop.sql": "DROP TABLE public.agent_context;"},
     "table_or_schema_drop_not_resolved"),
    ({"supabase/migrations/0002_rename.sql": "ALTER POLICY access ON public.agent_context RENAME TO other;"},
     "policy_or_table_rename_not_resolved"),
])
def test_incomplete_or_ambiguous_migration_inventory_makes_no_absence_claim(extra, limitation):
    facts = collect(policy("SELECT"), **extra)
    result = facts["records"][0]
    assert limitation in facts["limitations"]
    assert result["sequence_status"] == "incomplete_or_ambiguous"
    assert result["commands_in_declared_sequence"] is None
    assert result["missing_command_declarations"] is None


def test_unqualified_policy_schema_is_not_assumed_to_be_public():
    facts = collect(policy("ALL", table="agent_context"))
    result = facts["records"][0]
    assert "unqualified_policy_schema" in result["limitations"]
    assert result["missing_command_declarations"] is None
    assert result["policy_history"][0]["schema"] is None


@pytest.mark.parametrize("path", ["tests/migrations/0002_policy.sql", "vendor/migrations/0002_policy.sql",
                                  "node_modules/pkg/migrations/0002_policy.sql",
                                  "supabase/migrations/archive/0002_policy.sql"])
def test_test_vendor_and_archived_sql_are_not_current_migration_evidence(path):
    facts = collect(policy("SELECT"), **{path: policy("ALL", name="other")})
    assert facts["excluded_files"] == 1
    assert facts["records"][0]["missing_command_declarations"] == ["INSERT"]
    assert all(p["file"] != path for p in facts["records"][0]["policy_history"])


@pytest.mark.parametrize("advice", ["Rotate the service-role key.", "Use timingSafeEqual for the JWT check.",
                                    "Keep the service-role client; minimize returned columns.",
                                    "Implement an anonymous feedback form."])
def test_unrelated_recommendations_are_not_tagged(advice):
    facts = {"rls_recommendations": collect(policy("SELECT"))}
    assert rls_recommendation_context(recommendation(fix_hint=advice), facts) == []


def test_context_requires_same_source_file():
    facts = {"rls_recommendations": collect(policy("SELECT"))}
    assert rls_recommendation_context(recommendation(file="app/other.ts"), facts) == []


def test_comments_strings_aliases_and_dynamic_tables_do_not_become_write_evidence():
    code = '''
// db.from('agent_context').delete();
const text = "db.from('agent_context').insert(secret)";
const query = db.from('agent_context'); query.delete();
db.from(tableName).insert(secret);
db.from(`agent_context`).delete();
db.from('agent_context').select('*');
'''
    facts = collect_rls_recommendations(archive({"app/route.ts": code}))
    assert facts["records"] == []
    assert "dynamic_or_unsupported_table" in facts["limitations"]


def test_predicate_credentials_and_payload_literals_never_enter_context():
    facts = collect_rls_recommendations(archive({
        "app/api/context/route.ts": "await db.from('agent_context').insert({token:'credential-do-not-emit'});",
        "supabase/migrations/0001_policy.sql": "CREATE POLICY access ON public.agent_context FOR INSERT "
        "TO authenticated WITH CHECK (token = 'credential-do-not-emit');",
    }))
    context = rls_recommendation_context(recommendation(), {"rls_recommendations": facts})
    encoded = json.dumps({"facts": facts, "context": context})
    assert "credential-do-not-emit" not in encoded
    assert "auth.uid" not in encoded
    assert facts["records"][0]["policy_history"][0]["with_check_present"] is True


def test_missing_migrations_are_unknown_not_a_permission_verdict():
    facts = collect_rls_recommendations(archive({"app/route.ts": "await db.from('agent_context').delete();"}))
    assert facts["records"][0]["missing_command_declarations"] is None
    assert facts["records"][0]["sequence_status"] == "incomplete_or_ambiguous"


def test_restrictive_or_wrong_role_command_is_never_claimed_to_grant_access():
    facts = collect("CREATE POLICY closed ON public.agent_context AS RESTRICTIVE FOR INSERT "
                    "TO service_role WITH CHECK(false);")
    record = facts["records"][0]
    assert record["missing_command_declarations"] == []
    assert record["policy_history"][0]["permissive"] is False
    assert record["policy_history"][0]["roles"] == ["service_role"]
    context = rls_recommendation_context(recommendation(), {"rls_recommendations": facts})[0]
    assert "do not prove" in context["summary"]


def test_budget_is_reported_and_not_silent(monkeypatch):
    import app.scan.rls_recommendations as module
    monkeypatch.setattr(module, "MAX_FILES", 1)
    facts = collect(policy("SELECT"))
    assert "scan_budget_reached" in facts["limitations"]
    assert facts["records"][0]["missing_command_declarations"] is None
