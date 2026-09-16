"""Report context must not manufacture a source language or hide credentials."""

import io
import zipfile

import pytest

from app.scan.checks import run_checks
from app.scan.secrets import scan_secrets


def archive(path: str, body: str) -> io.BytesIO:
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as bundle:
        bundle.writestr("README.md", "Example project")
        bundle.writestr(path, body)
    result.seek(0)
    return result


@pytest.mark.parametrize("path,context", [
    ("tests/test_apps/.env", "test_file"),
    ("examples/demo/.env", "doc_example"),
    ("app/.env", None),
])
def test_env_path_context_does_not_downgrade_real_credential(path, context):
    # Build a format-valid synthetic token without committing a credential.
    value = "ghp_" + "a" * 36
    result = run_checks(archive(path, "API_TOKEN=" + value))
    found = next(f for f in result if f.rule_id == "env-file-committed")
    assert found.context == context
    assert found.severity == "critical"
    assert value not in repr(found)


def test_noncredential_env_fixture_keeps_context_for_secondary_report():
    result = run_checks(archive("tests/test_apps/.env", "FOO=bar\nSPAM=eggs\n"))
    found = next(f for f in result if f.rule_id == "env-file-committed")
    assert found.context == "test_file"
    assert found.severity == "medium"


@pytest.mark.parametrize("path,sql", [("docs/config.rst", False), ("schema.sql", True)])
def test_assignment_language_comes_from_source_not_rule_name(path, sql):
    found = next(f for f in scan_secrets(archive(path, "SECRET_KEY = '" + "a" * 24 + "'\n"))
                 if f.rule_id == "sql-secret-assignment")
    assert ("SQL/PLpgSQL" in found.title) is sql
    assert found.masked and "a" * 24 not in repr(found)
