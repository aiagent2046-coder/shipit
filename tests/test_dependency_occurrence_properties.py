"""Origins survive identity deduplication; evidence never combines two origins.

Synthetic npm lockfiles only; no repository code or dependencies are executed.
The independent model merges source facts, without calling production helpers.
"""
import io
import json
import zipfile

import pytest
from hypothesis import example, given, settings, strategies as st

from app.sca import lockfiles
from app.scan.cve_match import match_archive


PROPERTY_SETTINGS = settings(max_examples=24, derandomize=True)
FACT = st.tuples(st.sampled_from([False, None, True]), st.booleans())
LAYOUTS = st.lists(st.lists(FACT, min_size=1, max_size=3), min_size=1, max_size=4)
FIELDS = ("manifest", "line", "direct", "development", "dependency_groups")


def _archive(files, *, reverse=False):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in list(files.items())[::(-1 if reverse else 1)]:
            archive.writestr(name, content)
    return output.getvalue()


def _fixtures(layout, versions=None, *, reverse_entries=False):
    """A row is (development, direct); aliases allow independent direct flags."""
    files, expected = {}, {}
    for project, facts in enumerate(layout):
        manifest = f"apps/p{project}/package-lock.json"
        declarations, entries = {}, {}
        grouped = {}
        for index, (development, direct) in enumerate(facts):
            version = versions[project][index] if versions else "1.2.3"
            installed = f"alias{index}" if direct else "widget"
            location = (f"node_modules/{installed}" if direct
                        else f"node_modules/parent{index}/node_modules/widget")
            entry = {"name": "widget", "version": version, "dev": development}
            entries[location] = entry
            if direct:
                group = "devDependencies" if development is True else "dependencies"
                declarations.setdefault(group, {})[installed] = f"npm:widget@{version}"
            grouped.setdefault(version, []).append((development, direct))
        if reverse_entries:
            entries = dict(reversed(list(entries.items())))
        files[manifest] = json.dumps({"lockfileVersion": 3, "packages": {"": declarations, **entries}})
        files[manifest.replace("package-lock.json", "package.json")] = json.dumps(declarations)
        for version, rows in grouped.items():
            # Specification oracle: runtime wins, then unknown, then dev.
            scopes = [scope for scope, _ in rows]
            scope = False if False in scopes else None if None in scopes else True
            occurrence = {
                "manifest": manifest, "line": 0, "direct": any(direct for _, direct in rows),
                "development": scope,
                "dependency_groups": ("devDependencies",) if True in scopes else (),
            }
            expected.setdefault(version, []).append(occurrence)
    return files, expected


def _facts(occurrence):
    return {name: getattr(occurrence, name) for name in FIELDS}


def _canonical_key(occurrence):
    scope = occurrence["development"]
    priority = 0 if scope is False else 1 if scope is None else 2
    return priority, occurrence["manifest"], occurrence["line"]


def _assert_inventory(data, expected):
    inventory = lockfiles.collect_dependency_inventory(data)
    assert inventory.found == len(expected)
    assert len(inventory.dependencies) == len(expected)
    assert inventory.incomplete_manifests == {}
    by_version = {dependency.version: dependency for dependency in inventory.dependencies}
    assert set(by_version) == set(expected)
    for version, occurrences in expected.items():
        dependency = by_version[version]
        actual = [_facts(item) for item in getattr(dependency, "occurrences", ())]
        assert sorted(actual, key=lambda item: item["manifest"]) == occurrences
        assert _facts(dependency) == min(occurrences, key=_canonical_key)
    return inventory


def _catalog(*, unknown=False):
    return {
        "schema_version": 1,
        "source": {"repository": "https://github.com/CVEProject/cvelistV5",
                   "commit": "a" * 40, "generated_at": "2026-09-17T10:00:00Z"},
        "packages": {"npm:widget": [{
            "id": "CVE-2026-12345", "default_status": "unaffected", "versions": [{
                "version": "1.0.0", "lessThan": "2.0.0",
                "status": "affected", "versionType": "custom" if unknown else "semver",
            }],
        }]},
    }


def _json_origins(occurrences):
    return [{
        "manifest": item["manifest"], "line": item["line"], "direct": item["direct"],
        "dependency_scope": ("runtime" if item["development"] is False else
                             "development" if item["development"] is True else "unknown"),
        "dependency_groups": list(item["dependency_groups"]),
    } for item in occurrences]


def _assert_report(data, expected, *, unknown=False):
    result = match_archive(data, _catalog(unknown=unknown))
    coverage = result["coverage"]
    assert coverage["dependencies_found"] == len(expected)
    assert coverage["dependencies_checked"] == len(expected)
    assert coverage["advisory_evaluations"] == len(expected)
    assert coverage["status_counts"] == {
        "affected": 0 if unknown else len(expected), "unaffected": 0,
        "unknown": len(expected) if unknown else 0, "not_in_catalog": 0,
    }
    if unknown:
        assert result["findings"] == []
        records = {item["version"]: item for item in coverage["details"]}
    else:
        records = {item["claim_evidence"]["installed_version"]: item["claim_evidence"]
                   for item in result["findings"]}
        assert len(result["findings"]) == len(expected)
    assert set(records) == set(expected)
    for version, origins in expected.items():
        record = records[version]
        assert record.get("occurrences_recorded") is True
        assert sorted(record.get("occurrences", []), key=lambda item: item["manifest"]) == _json_origins(origins)


@pytest.mark.parametrize("unknown", [False, True], ids=["finding", "unknown-detail"])
def test_two_manifests_retain_both_origins_without_duplicate_assessments(unknown):
    # Directness from the dev origin must not be attached to the runtime origin.
    files, expected = _fixtures([[(True, True)], [(False, False)]])
    data = _archive(files)
    _assert_report(data, expected, unknown=unknown)
    _assert_inventory(data, expected)


@PROPERTY_SETTINGS
@given(layout=LAYOUTS)
@example(layout=[[(True, True), (False, False)], [(None, True)]])
def test_file_and_entry_order_preserve_merged_origins_and_canonical_scalars(layout):
    files, expected = _fixtures(layout)
    reordered, _ = _fixtures(layout, reverse_entries=True)
    _assert_inventory(_archive(files), expected)
    _assert_inventory(_archive(reordered, reverse=True), expected)
    _assert_report(_archive(reordered, reverse=True), expected)


@PROPERTY_SETTINGS
@given(layout=st.lists(st.lists(FACT, min_size=1, max_size=2), min_size=2, max_size=4))
def test_adding_then_removing_manifest_changes_origins_not_lookup_count(layout):
    full_files, full_expected = _fixtures(layout)
    base_files, base_expected = _fixtures(layout[:-1])
    _assert_inventory(_archive(base_files), base_expected)
    _assert_inventory(_archive(full_files), full_expected)
    _assert_report(_archive(full_files), full_expected)
    removed_manifest = f"apps/p{len(layout) - 1}/"
    remaining = {name: value for name, value in full_files.items() if not name.startswith(removed_manifest)}
    _assert_inventory(_archive(remaining), base_expected)
    _assert_report(_archive(remaining), base_expected)


@PROPERTY_SETTINGS
@given(patch=st.integers(0, 98), facts=st.lists(FACT, min_size=3, max_size=3))
def test_different_versions_remain_independent_while_same_version_duplicates_merge(patch, facts):
    first, second = f"1.0.{patch}", f"1.0.{patch + 1}"
    files, expected = _fixtures([facts[:2], facts[2:]], [[first, second], [first]])
    data = _archive(files)
    _assert_inventory(data, expected)
    _assert_report(data, expected)


def test_repeated_requirement_pins_keep_first_positive_line_and_one_origin():
    data = _archive({"requirements.txt": "# generated fixture\nwidget==1.2.3\n\nwidget==1.2.3\n"})
    _assert_inventory(data, {"1.2.3": [{
        "manifest": "requirements.txt", "line": 2, "direct": False,
        "development": None, "dependency_groups": (),
    }]})


def test_legacy_dependency_has_explicit_fallback_without_complete_origin_claim():
    dependency = lockfiles.Dependency("npm", "widget", "1.2.3", "old/package-lock.json",
                                     line=7, direct=True, development=None,
                                     dependency_groups=("custom",))
    helper = getattr(lockfiles, "dependency_occurrences", None)
    assert callable(helper), "Legacy dependencies need a deliberate occurrence fallback"
    assert getattr(dependency, "occurrences", ()) == ()
    occurrences = helper(dependency)
    assert isinstance(occurrences, tuple)
    assert [_facts(item) for item in occurrences] == [_facts(dependency)]
