"""Platform applicability and source paths, including the Flask pilot regression."""

from __future__ import annotations

import io
from pathlib import Path
import zipfile

import pytest

from app.scan.rls import RULE_ID, WRITE_RULE_ID, read_committed_sql, scan_rls


PRIVATE = "CREATE TABLE public.users (id uuid PRIMARY KEY, email text);\n"
PROTECTED = PRIVATE + "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;\n"
SQLITE = """
DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS post;
CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);
CREATE TABLE post (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  FOREIGN KEY (author_id) REFERENCES user (id)
);
"""


def archive(entries):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    result.seek(0)
    return result


@pytest.mark.parametrize("prefix", ["", "flask-archive/"])
def test_flask_tutorial_is_not_a_supabase_project_and_keeps_its_path(prefix):
    path = "examples/tutorial/flaskr/schema.sql"
    entries = {prefix + path: SQLITE}
    assert scan_rls(archive(entries)) == []
    text, paths = read_committed_sql(archive(entries))
    assert paths == [path]
    assert "AUTOINCREMENT" in text


@pytest.mark.parametrize("path", [
    "schema.sql", "db/schema.sql", "migrations/0001.sql", "apps/service/sql/schema.sql",
    "not-supabase/migrations/0001.sql", "supabase-backup/migrations/0001.sql",
])
def test_postgresql_alone_does_not_establish_supabase_default_grants(path):
    assert scan_rls(archive({path: PRIVATE})) == []
    # Mutation: the same supported SQL in a declared Supabase migration tree.
    findings = scan_rls(archive({"supabase/migrations/0001.sql": PRIVATE}))
    assert {f.rule_id for f in findings} == {RULE_ID, WRITE_RULE_ID}


@pytest.mark.parametrize("marker", [
    "-- Supabase auth.users auth.uid() TO anon GRANT SELECT ON public.users TO anon;\n",
    "/* CREATE POLICY public_access ON public.users TO anon USING (true); */\n",
    "SELECT 'supabase/migrations/0001.sql; auth.uid(); TO anon';\n",
    "CREATE TABLE audit (user_id uuid REFERENCES auth.users(id));\n",
])
def test_text_markers_and_auth_schema_names_do_not_establish_platform(marker):
    assert scan_rls(archive({"schema.sql": marker + PRIVATE})) == []


@pytest.mark.parametrize("prefix", ["", "project-archive/"])
def test_a_supabase_app_cannot_lend_context_or_policies_to_a_sqlite_neighbor(prefix):
    findings = scan_rls(archive({
        prefix + "apps/website/supabase/migrations/0001.sql": PROTECTED,
        prefix + "apps/tutorial/examples/flaskr/schema.sql": SQLITE,
        prefix + "apps/tutorial/client.ts": "import { createClient } from '@supabase/supabase-js';",
    }))
    assert findings == []


@pytest.mark.parametrize("prefix", ["", "project-archive/"])
def test_supabase_projects_with_identical_table_names_have_separate_histories(prefix):
    exposed_path = "apps/open/supabase/migrations/0001.sql"
    findings = scan_rls(archive({
        prefix + exposed_path: PRIVATE,
        prefix + "apps/closed/supabase/migrations/0002.sql": PROTECTED,
        # This must not alter the open project's state just because its
        # filename sorts after the open migration.
        prefix + "apps/closed/supabase/migrations/0003.sql":
            "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;",
    }))
    assert {f.rule_id for f in findings} == {RULE_ID, WRITE_RULE_ID}
    assert {f.file for f in findings} == {exposed_path}
    findings = scan_rls(archive({
        prefix + "apps/closed/supabase/migrations/0001.sql": PROTECTED,
        prefix + "apps/open/supabase/migrations/0002.sql": PRIVATE,
    }))
    assert {f.file for f in findings} == {"apps/open/supabase/migrations/0002.sql"}


@pytest.mark.parametrize("path", [
    "supabase/schema.sql", "supabase/schemas/users.sql",
    "supabase/migrations/0002_users.sql", "supabase/migrations/archive/0002_users.sql",
])
@pytest.mark.parametrize("prefix", ["", "repo-export/"])
def test_finding_names_the_table_declaration_instead_of_the_first_sql(path, prefix):
    findings = scan_rls(archive({
        prefix + "supabase/migrations/0001_setup.sql": "CREATE SCHEMA IF NOT EXISTS public;",
        prefix + path: PRIVATE,
    }))
    assert {f.rule_id for f in findings} == {RULE_ID, WRITE_RULE_ID}
    assert {f.file for f in findings} == {path}


@pytest.mark.parametrize("rule", [RULE_ID, WRITE_RULE_ID])
@pytest.mark.parametrize("case", ["sqlite-tutorial", "generic-postgresql", "mixed-sql-scopes"])
def test_platform_corpus_negatives_have_a_positive_mutation(rule, case):
    case_dir = Path(__file__).parent / "detectors" / rule / "negative" / case
    files = {
        path.relative_to(case_dir).as_posix().removesuffix(".fixture"): path.read_text()
        for path in case_dir.rglob("*.fixture")
    }
    assert scan_rls(archive(files)) == []
    # Keep the complete negative repository and add a real exposed Supabase
    # schema. The applicability gate must not disable the rule repository-wide.
    files["new-app/supabase/migrations/0001.sql"] = PRIVATE
    findings = scan_rls(archive(files))
    assert rule in {f.rule_id for f in findings}
    assert {f.file for f in findings} == {"new-app/supabase/migrations/0001.sql"}
