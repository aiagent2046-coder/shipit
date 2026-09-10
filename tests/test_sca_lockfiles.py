"""The lockfile readers: what is a resolvable dependency, and what is not.

The negative cases matter more here than the positive ones. A manifest line
that looks like a dependency but carries no resolved version -- a range, an
option, a direct reference, a hash continuation -- must not reach the network
lookup, because a lookup on a guessed version produces an advisory about
something the project may never have installed.
"""
from __future__ import annotations

import io
import json
import zipfile

import pytest

from app.sca.lockfiles import (MAX_DEPENDENCIES, collect_dependencies,
                               normalize_pypi)


def make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in entries.items():
            zf.writestr(name, text)
    return buf.getvalue()


def lockfile_v3() -> str:
    return json.dumps({
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "0.1.0"},
            "node_modules/lodash": {"version": "4.17.4"},
            "node_modules/@scope/tool": {"version": "2.0.0"},
            "node_modules/a/node_modules/hoisted": {"version": "1.2.3"},
            "node_modules/workspace": {"link": True},
        },
    })


def test_package_lock_resolves_installed_versions():
    deps, manifests = collect_dependencies(make_zip({
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        "package-lock.json": lockfile_v3(),
    }))
    found = {(d.ecosystem, d.name, d.version) for d in deps}
    assert ("npm", "lodash", "4.17.4") in found, "a range must resolve to the lockfile's version"
    assert ("npm", "@scope/tool", "2.0.0") in found
    assert ("npm", "hoisted", "1.2.3") in found, "the last node_modules segment names the package"
    assert manifests == ["package-lock.json"]


def test_entries_that_are_not_packages_are_skipped():
    deps, _ = collect_dependencies(make_zip({"package-lock.json": lockfile_v3()}))
    assert all(d.version for d in deps)
    assert "app" not in {d.name for d in deps}, "the root project is not a dependency"
    assert "workspace" not in {d.name for d in deps}, "a link entry has no version"


def test_direct_dependency_flag_comes_from_package_json():
    deps, _ = collect_dependencies(make_zip({
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        "package-lock.json": lockfile_v3(),
    }))
    by_name = {d.name: d for d in deps}
    assert by_name["lodash"].direct is True
    assert by_name["hoisted"].direct is False
    assert by_name["hoisted"].manifest == "package-lock.json"


def test_legacy_lockfile_version_one_is_read():
    legacy = json.dumps({
        "lockfileVersion": 1,
        "dependencies": {"lodash": {"version": "4.17.4"},
                         "chalk": {"version": "2.4.2"}},
    })
    deps, _ = collect_dependencies(make_zip({"package-lock.json": legacy}))
    assert {(d.name, d.version) for d in deps} == {("lodash", "4.17.4"),
                                                  ("chalk", "2.4.2")}


def test_unreadable_lockfile_is_not_an_empty_repository():
    deps, manifests = collect_dependencies(make_zip({
        "package-lock.json": "{ this is not json"}))
    assert deps == []
    assert manifests == ["package-lock.json"], "the file was found and could not be read"


@pytest.mark.parametrize("line,expected", [
    ("django==2.0.0", ("django", "2.0.0")),
    ("Django[argon2]==2.0.0  # pinned", ("django", "2.0.0")),
    ("zope.interface==5.4.0", ("zope-interface", "5.4.0")),
    ("my_package==1.0.0", ("my-package", "1.0.0")),
])
def test_requirements_pins_are_resolved_and_normalized(line, expected):
    deps, _ = collect_dependencies(make_zip({"requirements.txt": line + "\n"}))
    assert [(d.name, d.version) for d in deps] == [expected]
    assert deps[0].ecosystem == "PyPI"


@pytest.mark.parametrize("line", [
    "django>=2.0",                      # a range is not a version
    "django~=2.0.0",
    "-r requirements-dev.txt",          # an option is not a package
    "-e .",
    "git+https://github.com/django/django.git#egg=django",
    "django @ https://example.com/django-2.0.0.tar.gz",
    "django==2.0.0 \\",                 # a hash continuation
    "# django==2.0.0",
    "django",                           # unpinned
])
def test_requirements_lines_without_a_resolved_version_are_skipped(line):
    deps, manifests = collect_dependencies(make_zip({"requirements.txt": line + "\n"}))
    assert deps == []
    assert manifests == ["requirements.txt"]


def test_requirements_records_the_line_it_read():
    deps, _ = collect_dependencies(make_zip({
        "requirements.txt": "\n".join(["# first", "flask==1.0.0", "django==2.0.0"]) + "\n"}))
    assert {d.line for d in deps} == {2, 3}


def test_poetry_lock_packages_are_read():
    poetry = "\n".join([
        "[[package]]",
        'name = "Django"',
        'version = "2.0.0"',
        "",
        "[[package]]",
        'name = "requests"',
        'version = "2.19.0"',
    ])
    deps, manifests = collect_dependencies(make_zip({"poetry.lock": poetry}))
    assert {(d.name, d.version, d.ecosystem) for d in deps} == {
        ("django", "2.0.0", "PyPI"), ("requests", "2.19.0", "PyPI")}
    assert manifests == ["poetry.lock"]


def test_go_sum_reads_modules_and_ignores_the_go_mod_hashes():
    go = "\n".join([
        "github.com/gin-gonic/gin v1.6.3 h1:abc=",
        "github.com/gin-gonic/gin v1.6.3/go.mod h1:def=",
        "golang.org/x/text v0.3.3 h1:ghi=",
    ])
    deps, manifests = collect_dependencies(make_zip({"go.sum": go}))
    assert [(d.name, d.version, d.ecosystem) for d in deps] == [
        ("github.com/gin-gonic/gin", "v1.6.3", "Go"),
        ("golang.org/x/text", "v0.3.3", "Go"),
    ]
    assert manifests == ["go.sum"]


def test_vendored_lockfiles_inside_node_modules_are_ignored():
    deps, manifests = collect_dependencies(make_zip({
        "web/node_modules/some-package/package-lock.json": lockfile_v3()}))
    assert deps == []
    assert manifests == []


def test_the_root_lockfile_wins_over_a_nested_one():
    deps, manifests = collect_dependencies(make_zip({
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/rootdep": {"version": "1.0.0"}}}),
        "apps/web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/nesteddep": {"version": "9.9.9"}}}),
    }))
    assert manifests[0] == "package-lock.json"
    assert {"rootdep", "nesteddep"} == {d.name for d in deps}


def test_the_same_version_twice_is_one_dependency():
    deps, _ = collect_dependencies(make_zip({
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/a": {"version": "1.0.0"}}}),
        "apps/api/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/a": {"version": "1.0.0"}}}),
    }))
    assert len(deps) == 1


def test_the_lookup_is_bounded():
    packages = {f"node_modules/pkg{i}": {"version": "1.0.0"}
                for i in range(MAX_DEPENDENCIES + 50)}
    deps, _ = collect_dependencies(make_zip({
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": packages})}))
    assert len(deps) == MAX_DEPENDENCIES


def test_an_archive_with_no_lockfile_yields_nothing():
    deps, manifests = collect_dependencies(make_zip({"src/app.py": "print(1)\n"}))
    assert (deps, manifests) == ([], [])


@pytest.mark.parametrize("raw,expected", [
    ("Django", "django"), ("zope.interface", "zope-interface"),
    ("my_package", "my-package"), ("a__b", "a-b"), (" A.B-c ", "a-b-c"),
])
def test_pypi_normalization(raw, expected):
    assert normalize_pypi(raw) == expected
