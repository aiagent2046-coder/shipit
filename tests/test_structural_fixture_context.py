"""Stored corpus files must not become instructions to delete test inputs."""

import io
import zipfile

import pytest

from app.scan.checks import find_committed_env_files, run_checks
from app.scan.secrets import scan_secrets


def archive(entries, prefix):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as handle:
        handle.writestr(prefix + "README.md", "A project")
        for name, value in entries.items():
            handle.writestr(prefix + name, value)
    output.seek(0)
    return output


@pytest.mark.parametrize("prefix", ["", "project-main/"])
def test_inert_env_inventory_does_not_hide_secret_candidates(prefix):
    name = "tests/detectors/env-file-committed/positive/sample/.env.fixture"
    # Synthetic value assembled so the test source is not itself a key literal.
    value = "AWS_ACCESS_KEY_ID=" + "AKIA" + "B7C8D9E0F1G2H3J4" + "\n"
    data = archive({name: value}, prefix)
    assert "env-file-committed" not in {f.rule_id for f in run_checks(data)}
    data.seek(0)
    assert any(f.rule_id == "aws-access-key-id" for f in scan_secrets(data))
    assert find_committed_env_files([prefix + name]) == []


@pytest.mark.parametrize("prefix", ["", "project-main/"])
def test_actual_env_file_inside_tests_remains_reportable(prefix):
    name = "tests/stand/.env"
    findings = run_checks(archive({name: "PORT=3000\n"}, prefix))
    assert any(f.rule_id == "env-file-committed" and f.file == name for f in findings)


@pytest.mark.parametrize("prefix", ["", "project-main/"])
@pytest.mark.parametrize("suffix, expected", [(".py.fixture", False), (".py", True)])
def test_stored_dependency_corpus_vs_materialized_tree(prefix, suffix, expected):
    directory = "tests/detectors/dependency-dir-committed/positive/sample/venv"
    entries = {f"{directory}/lib/m{i}{suffix}": "x = 1\n" for i in range(25)}
    findings = run_checks(archive(entries, prefix))
    dependencies = [f for f in findings if f.rule_id == "dependency-dir-committed"]
    assert bool(dependencies) is expected
    if expected:
        assert dependencies[0].file == directory


@pytest.mark.parametrize("directory", ["myvenv", "custom_vendor", "old_node_modules"])
def test_dependency_names_match_complete_segments(directory):
    entries = {f"src/{directory}/module{i}.py": "x = 1\n" for i in range(25)}
    assert not any(f.rule_id == "dependency-dir-committed"
                   for f in run_checks(archive(entries, "project-main/")))


def test_mixed_test_tree_is_not_suppressed_as_a_fixture():
    entries = {f"tests/venv/lib/m{i}.py.fixture": "x = 1\n" for i in range(25)}
    entries["tests/venv/pyvenv.cfg"] = "include-system-site-packages = false\n"
    assert any(f.rule_id == "dependency-dir-committed"
               for f in run_checks(archive(entries, "project-main/")))


def test_outer_dependency_directory_counts_nested_members_once():
    entries = {f"vendor/venv/lib/m{i}.py": "x = 1\n" for i in range(15)}
    entries.update({f"vendor/pkg/m{i}.php": "<?php\n" for i in range(15)})
    findings = [f for f in run_checks(archive(entries, "project-main/"))
                if f.rule_id == "dependency-dir-committed"]
    assert len(findings) == 1
    assert findings[0].file == "vendor"
    assert "30 files" in findings[0].title
