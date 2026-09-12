"""Build output must not displace application checks or widen secret exclusions."""

import pytest

from app.report.sarif import build_sarif
from app.scan.cookie_flags import scan_cookie_flags
from app.scan.manifest import scan_manifest
from app.scan.secrets import scan_secrets
from app.scan.static import run_static_scan
from tests.test_cookie_flags import PYTHON_POSITIVE, TS_POSITIVE
from tests.test_dependency_scan_budget import CASES, archive
from tests.test_rule_coverage import assert_accounting, harmless
from tests.test_secrets import FAKE_GHP


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
@pytest.mark.parametrize("directory", [".next", "dist", "build"])
@pytest.mark.parametrize("prefix,separator", [("", "/"), ("project/web/", "/"), ("project/web/", "\\")])
def test_500_build_files_cannot_displace_own_source_in_either_archive_order(
    scanner, rule_id, filename, source, directory, prefix, separator,
):
    def path(value):
        return (prefix + value).replace("/", separator)

    own = (path(f"app/{filename}"), source)
    generated = [(path(f"{directory}/chunks/{number}/{filename}"), harmless(filename)) for number in range(500)]
    expected = scanner(archive([own]))
    assert [finding.rule_id for finding in expected] == [rule_id]
    for files in ([*generated, own], [own, *generated]):
        coverage = {}
        assert scanner(archive(files), coverage=coverage) == expected
        assert_accounting(coverage, total=501, eligible=1, attempted=1, analyzed=1,
                          exclusions={"generated_build": 500})
    # The same defect in build output must not add a duplicate finding.
    assert scanner(archive([(path(f"{directory}/migrations/{filename}"), source), own])) == expected


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
def test_build_exclusion_does_not_conceal_the_remaining_own_file_limit(scanner, rule_id, filename, source):
    files = [(f"project/dist/{number}/{filename}", harmless(filename)) for number in range(500)]
    files += [(f"project/app/{number}/{filename}", harmless(filename)) for number in range(839)]
    files.append((f"project/app/{filename}", source))
    coverage = {}
    assert scanner(archive(files), coverage=coverage) == []
    assert_accounting(coverage, total=1340, eligible=840, attempted=400, analyzed=400,
                      exclusions={"generated_build": 500}, skips={"file_limit": 440})


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
def test_build_only_archive_has_no_eligible_source_even_for_unreadable_entries(scanner, rule_id, filename, source):
    files = [(f".next/{filename}", b"\xff"), (f"dist/{filename}", "#" * 400_001),
             (f"build/{filename}", source)]
    coverage = {}
    assert scanner(archive(files), coverage=coverage) == []
    assert_accounting(coverage, total=3, eligible=0, attempted=0, analyzed=0,
                      exclusions={"generated_build": 3})


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
def test_nested_categories_are_counted_once_without_hiding_application_migrations(scanner, rule_id, filename, source):
    files = [(f"vendor/pkg/.next/{filename}", source), (f".next/server/node_modules/pkg/{filename}", source),
             (f"dist/tests/{filename}", source), (f"app/migrations/{filename}", source)]
    coverage = {}
    findings = scanner(archive(files), coverage=coverage)
    assert [finding.file for finding in findings] == [f"app/migrations/{filename}"]
    assert_accounting(coverage, total=4, eligible=1, attempted=1, analyzed=1,
                      exclusions={"dependency_tree": 2, "generated_build": 1})


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
@pytest.mark.parametrize("directory", ["builder", "distances", ".next-custom", "rebuild"])
def test_similar_directory_names_remain_own_source(scanner, rule_id, filename, source, directory):
    coverage = {}
    findings = scanner(archive([(f"project/{directory}/{filename}", source)]), coverage=coverage)
    assert [finding.rule_id for finding in findings] == [rule_id]
    assert_accounting(coverage, total=1, eligible=1, attempted=1, analyzed=1)


@pytest.mark.parametrize("filename,source", [("login.py", PYTHON_POSITIVE), ("login.ts", TS_POSITIVE)])
@pytest.mark.parametrize("directory", [".next", "dist", "build"])
def test_cookie_budget_also_excludes_build_output(filename, source, directory):
    own = (f"project/app/{filename}", source)
    generated = [(f"project/{directory}/{number}/{filename}", harmless(filename)) for number in range(500)]
    expected = scan_cookie_flags(archive([own]))
    assert len(expected) == 1
    for files in ([*generated, own], [own, *generated]):
        assert scan_cookie_flags(archive(files)) == expected
    assert scan_cookie_flags(archive([(f"project/{directory}/{filename}", source)])) == []


def test_secret_detection_and_its_existing_directory_policy_are_preserved():
    source = f"token = '{FAKE_GHP}'\n"
    scanned = ["app", "vendor/pkg", "site-packages/pkg", "bower_components/pkg", ".tox/pkg", ".nox/pkg"]
    excluded = [".next", "dist", "build", "node_modules/pkg", ".git", "venv/pkg", ".venv/pkg"]
    files = [(f"project/{directory}/config.py", source) for directory in [*scanned, *excluded]]
    coverage = {}
    findings = scan_secrets(archive(files), coverage=coverage)
    assert {finding.file for finding in findings if finding.rule_id == "github-pat"} == {
        f"project/{directory}/config.py" for directory in scanned
    }
    assert FAKE_GHP not in repr(findings)
    assert coverage == {"files_total": 13, "files_read": 6, "files_scanned": 6,
                        "lossy_decoded_files": 0, "exclusions": {"excluded_directory": 7}}


def test_generated_counts_survive_static_manifest_and_sarif_with_secret_findings():
    files = [(f"project/.next/chunk_{number}.py", "pass\n") for number in range(500)]
    files += [("project/app/client.py", 'import requests\nrequests.get("https://example.com", verify=False)\n'),
              ("project/vendor/config.py", f"token = '{FAKE_GHP}'\n")]
    stream = archive(files)
    data = stream.getvalue()
    static = run_static_scan(stream)
    assert any(finding["rule_id"] == "tls-verification-disabled" for finding in static["findings"])
    assert any(finding["rule_id"] == "github-pat" and finding["file"] == "project/vendor/config.py"
               for finding in static["findings"])
    manifest = scan_manifest(data, "test", static, {}, None)
    assert manifest["rule_coverage"] == static["rule_coverage"]
    for record in manifest["rule_coverage"].values():
        assert_accounting(record, total=502, eligible=1, attempted=1, analyzed=1,
                          exclusions={"dependency_tree": 1, "generated_build": 500})
    sarif = build_sarif([], engine_version="test", score={"scan_manifest": manifest})
    assert sarif["runs"][0]["invocations"][0]["properties"]["ruleCoverage"] == manifest["rule_coverage"]
