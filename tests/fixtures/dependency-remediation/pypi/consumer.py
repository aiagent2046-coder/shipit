"""Probe installed Django/sqlparse; generated Python is parsed, never executed."""

import ast
import importlib.metadata
import json
from pathlib import Path

import django
import sqlparse
from django.conf import settings


def check_equal(actual, expected, label):
    # Explicit checks also run if PYTHONOPTIMIZE is enabled.
    if actual != expected:
        raise AssertionError(f"{label}: {actual!r} != {expected!r}")


consumer_version = importlib.metadata.version("Django")
check_equal(consumer_version, "5.2.10", "pinned Django consumer")
settings.configure(
    DATABASES={
        "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
    },
    INSTALLED_APPS=[],
    SECRET_KEY="disposable-remediation-contract",
)
django.setup()
from django.db import connection  # noqa: E402

check_equal(len(sqlparse.parse("SELECT 1; SELECT 2;")), 2, "two statements")
check_equal(
    connection.ops.prepare_sql_script("SELECT 'a;b'; SELECT 2;"),
    ["SELECT 'a;b';", "SELECT 2;"],
    "semicolon inside a literal",
)
check_equal(
    connection.ops.prepare_sql_script("-- a comment\nSELECT 1;"),
    ["SELECT 1;"],
    "SQL comment removal",
)
with connection.cursor() as cursor:
    cursor.execute("SELECT %s", ["O'Reilly — Пёс"])
    check_equal(cursor.fetchone(), ("O'Reilly — Пёс",), "quoted Unicode parameter")
connection.close()

sql = "select '\\foo\\'"
generated = sqlparse.format(sql, output_format="python")
try:
    tree = ast.parse(generated)
    passed = (
        len(tree.body) == 1
        and isinstance(tree.body[0], ast.Assign)
        and len(tree.body[0].targets) == 1
        and isinstance(tree.body[0].targets[0], ast.Name)
        and tree.body[0].targets[0].id == "sql"
        and ast.literal_eval(tree.body[0].value) == sql
    )
    outcome = "literal_roundtrip" if passed else "roundtrip_mismatch"
except SyntaxError:
    passed, outcome = False, "SyntaxError"
except (ValueError, TypeError):
    passed, outcome = False, "roundtrip_mismatch"

print(json.dumps({
    "package": "sqlparse",
    "installed_version": importlib.metadata.version("sqlparse"),
    "installed_path": str(Path(sqlparse.__file__).resolve()),
    "consumer": "Django",
    "consumer_version": consumer_version,
    "functional_checks": 4,
    "functional_passed": True,
    "regression": {
        "id": "python-snippet-backslash-escaping",
        "passed": passed,
        "outcome": outcome,
    },
}))
