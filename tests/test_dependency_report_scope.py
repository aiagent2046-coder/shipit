"""Report scope needs lock evidence; uncertain ownership must remain visible."""
import io
import json
import zipfile

import pytest

from app.sca import lockfiles, resolved_locks
from app.scan.cve_match import match_archive


def archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as packed:
        for name, text in files.items():
            packed.writestr(name, text)
    return stream.getvalue()


def catalog(ecosystem="PyPI"):
    return {"schema_version": 1, "source": {
        "repository": "https://github.com/CVEProject/cvelistV5", "commit": "a" * 40,
        "generated_at": "2026-09-16T00:00:00Z",
    }, "packages": {ecosystem + ":widget": [{
        "id": "CVE-2026-12345", "default_status": "unaffected", "versions": [{
            "version": "1.0.0", "lessThan": "2.0.0", "status": "affected",
            "versionType": "semver" if ecosystem == "npm" else "python",
        }],
    }]}}


def uv_lock(runtime="", dev='typing = [{name = "widget"}]', extra=""):
    return '''version = 1
revision = 3
[[package]]
name = "project"
version = "0.1.0"
source = {editable = "."}
dependencies = [''' + runtime + ''']
[package.dev-dependencies]
''' + dev + '''
[[package]]
name = "widget"
version = "1.5.0"
source = {registry = "https://pypi.org/simple"}
''' + extra


def evidence(files, ecosystem="PyPI"):
    result = match_archive(archive(files), catalog(ecosystem))
    finding, = result["findings"]
    assert finding["severity"] == "high"  # Development scope is not a severity override.
    assert result["coverage"]["status_counts"]["affected"] == 1
    return finding["claim_evidence"]


@pytest.mark.parametrize(("dev", "scope", "groups"), [
    (True, "development", ["devDependencies"]),
    (False, "runtime", []),
    ("untrusted", "unknown", []),
])
def test_npm_scope_and_directness_reach_evidence_without_changing_match(dev, scope, groups):
    files = {
        "package.json": json.dumps({"devDependencies": {"widget": "^1"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/widget": {"version": "1.5.0", "dev": dev},
        }}),
    }
    row = evidence(files, "npm")
    assert (row["dependency_scope"], row["direct"], row["dependency_groups"]) == (scope, True, groups)
    del files["package.json"]
    assert evidence(files, "npm")["direct"] is False


def test_requirements_scope_is_unknown_without_root_or_group_metadata():
    row = evidence({"requirements.txt": "widget==1.5.0\n"})
    assert (row["dependency_scope"], row["direct"], row["dependency_groups"]) == ("unknown", False, [])


def test_uv_declared_typing_group_is_development_and_can_also_be_runtime():
    row = evidence({"uv.lock": uv_lock()})
    assert (row["dependency_scope"], row["direct"], row["dependency_groups"]) == (
        "development", True, ["typing"])
    # A runtime path wins even if a development group also needs the same pin.
    row = evidence({"uv.lock": uv_lock(runtime='{name = "widget"}')})
    assert (row["dependency_scope"], row["dependency_groups"]) == ("runtime", ["typing"])


def test_uv_transitive_groups_and_cycles_are_resolved_without_recursion():
    text = uv_lock(dev='typing = [{name = "tool"}]', extra='''dependencies = [{name = "tool"}]
[[package]]
name = "tool"
version = "2.0.0"
source = {registry = "https://pypi.org/simple"}
dependencies = [{name = "widget"}]
''')
    row = evidence({"uv.lock": text})
    assert (row["dependency_scope"], row["direct"], row["dependency_groups"]) == (
        "development", False, ["typing"])
    row = evidence({"uv.lock": text.replace('dependencies = []', 'dependencies = [{name = "tool"}]', 1)})
    assert (row["dependency_scope"], row["dependency_groups"]) == ("runtime", ["typing"])


@pytest.mark.parametrize("mutation", ["no_root", "missing_ref", "fork", "second_root", "unreachable"])
def test_uv_uncertain_graph_does_not_claim_development_only(mutation):
    text = uv_lock()
    if mutation == "no_root":
        text = text.replace('{editable = "."}', '{registry = "https://pypi.org/simple"}')
    elif mutation == "missing_ref":
        text = text.replace('dependencies = []', 'dependencies = [{name = "absent"}]', 1)
    elif mutation == "fork":
        text += '''\n[[package]]
name = "widget"
version = "2.5.0"
source = {registry = "https://pypi.org/simple"}
'''
    elif mutation == "second_root":
        text += '''\n[[package]]
name = "other-project"
version = "0.1.0"
source = {virtual = "."}
'''
    else:
        text = text.replace('typing = [{name = "widget"}]', 'typing = []')
    row = evidence({"uv.lock": text})
    assert (row["dependency_scope"], row["dependency_groups"]) == ("unknown", [])


def test_uv_scope_budget_retains_pins_without_partial_development_claim(monkeypatch):
    monkeypatch.setattr(resolved_locks, "MAX_UV_SCOPE_STEPS", 0)
    row = evidence({"uv.lock": uv_lock()})
    assert (row["dependency_scope"], row["dependency_groups"]) == ("unknown", [])


def test_duplicate_pin_in_unknown_manifest_prevents_development_only_claim():
    files = {"uv.lock": uv_lock(), "nested/requirements.txt": "widget==1.5.0\n"}
    row = evidence(files)
    assert row["dependency_scope"] == "unknown"
    assert row["manifest"] == "nested/requirements.txt"
    files["uv.lock"] = uv_lock(runtime='{name = "widget"}')
    row = evidence(files)
    assert row["dependency_scope"] == "runtime"
    assert row["manifest"] == "uv.lock"


def test_nonproduction_exclusions_are_visible_before_selection_budget(monkeypatch):
    monkeypatch.setattr(lockfiles, "MAX_LOCKFILES", 1)
    paths = {
        "docs/package-lock.json": "non_production_documentation",
        "tests/requirements.txt": "non_production_tests",
        "examples/pyproject.toml": "non_production_examples",
        "node_modules/vendor/package.json": "vendored_dependency",
        "web/.next/package.json": "generated_next_build",
    }
    files = dict.fromkeys(paths, "invalid metadata")
    files["apps/runtime/requirements.txt"] = "widget==1.5.0\n"
    result = match_archive(archive(files), catalog())
    assert len(result["findings"]) == 1
    assert result["coverage"]["manifests"] == ["apps/runtime/requirements.txt"]
    assert result["coverage"]["incomplete_manifests"] == {}
    assert result["coverage"]["excluded_manifests"] == paths


def test_exclusion_overflow_is_counted_and_metadata_does_not_disable_matching(monkeypatch):
    monkeypatch.setattr(lockfiles, "MAX_EXCLUDED_MANIFESTS", 2)
    files = {"docs/package.json": " " * 2_000_001,
             "tests/requirements.txt": "bad", "examples/pyproject.toml": "bad",
             "node_modules/vendor/uv.lock": "bad", "requirements.txt": "widget==1.5.0\n"}
    result = match_archive(archive(files), catalog())
    assert len(result["findings"]) == 1
    assert len(result["coverage"]["excluded_manifests"]) == 2
    assert result["coverage"]["excluded_manifests_truncated"] == 2
    assert result["coverage"]["incomplete_manifests"] == {}
