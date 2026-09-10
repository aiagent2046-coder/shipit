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
import pathlib
import zipfile

import pytest

from app.sca.lockfiles import (MAX_DEPENDENCIES, collect_dependencies,
                               normalize_pypi, unusable_lockfiles)


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
    deps, manifests, _found = collect_dependencies(make_zip({
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        "package-lock.json": lockfile_v3(),
    }))
    found = {(d.ecosystem, d.name, d.version) for d in deps}
    assert ("npm", "lodash", "4.17.4") in found, "a range must resolve to the lockfile's version"
    assert ("npm", "@scope/tool", "2.0.0") in found
    assert ("npm", "hoisted", "1.2.3") in found, "the last node_modules segment names the package"
    assert manifests == ["package-lock.json"]


def test_entries_that_are_not_packages_are_skipped():
    deps, _, _found = collect_dependencies(make_zip({"package-lock.json": lockfile_v3()}))
    assert all(d.version for d in deps)
    assert "app" not in {d.name for d in deps}, "the root project is not a dependency"
    assert "workspace" not in {d.name for d in deps}, "a link entry has no version"


def test_direct_dependency_flag_comes_from_package_json():
    deps, _, _found = collect_dependencies(make_zip({
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
    deps, _, _found = collect_dependencies(make_zip({"package-lock.json": legacy}))
    assert {(d.name, d.version) for d in deps} == {("lodash", "4.17.4"),
                                                  ("chalk", "2.4.2")}


def test_unreadable_lockfile_is_not_an_empty_repository():
    deps, manifests, _found = collect_dependencies(make_zip({
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
    deps, _, _found = collect_dependencies(make_zip({"requirements.txt": line + "\n"}))
    assert [(d.name, d.version) for d in deps] == [expected]
    assert deps[0].ecosystem == "PyPI"


@pytest.mark.parametrize("line", [
    "django>=2.0",                      # a range is not a version
    "django~=2.0.0",
    "-r requirements-dev.txt",          # an option is not a package
    "-e .",
    "git+https://github.com/django/django.git#egg=django",
    "django @ https://example.com/django-2.0.0.tar.gz",
    "# django==2.0.0",
    "django",                           # unpinned
])
def test_requirements_lines_without_a_resolved_version_are_skipped(line):
    deps, manifests, _found = collect_dependencies(make_zip({"requirements.txt": line + "\n"}))
    assert deps == []
    assert manifests == ["requirements.txt"]


def test_requirements_records_the_line_it_read():
    deps, _, _found = collect_dependencies(make_zip({
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
    deps, manifests, _found = collect_dependencies(make_zip({"poetry.lock": poetry}))
    assert {(d.name, d.version, d.ecosystem) for d in deps} == {
        ("django", "2.0.0", "PyPI"), ("requests", "2.19.0", "PyPI")}
    assert manifests == ["poetry.lock"]


def test_a_pip_compile_pin_with_hashes_is_read():
    """The shape this repository generates for itself: the pin ends with a
    continuation backslash and the hashes follow on their own lines. Skipping
    every line that ends with a backslash -- which is what this did -- read the
    file's 37 pins as 0 dependencies."""
    compiled = "\n".join([
        "#",
        "# This file is autogenerated by pip-compile",
        "#",
        "annotated-doc==0.0.5 \\",
        "    --hash=sha256:117bac03a25ede5df5440e855b32d556049ca169ead221505badf432fed4b101 \\",
        "    --hash=sha256:c7e58ce09192557605d8bbd92836d7e1d520ac9580096042c0bfd197efacf1bb",
        "    # via fastapi",
        "anyio==4.15.0 \\",
        "    --hash=sha256:7ecd9937369ffce8bba0b5ccb9b3a9507b101b0ed50256aecfbab27e6c2acb99",
        "django>=2.0",                   # still a range, still not a version
    ]) + "\n"
    deps, manifests, _found = collect_dependencies(make_zip({"requirements.txt": compiled}))
    assert [(d.name, d.version) for d in deps] == [("annotated-doc", "0.0.5"),
                                                   ("anyio", "4.15.0")]
    assert manifests == ["requirements.txt"]


def test_this_repositorys_own_requirements_file_is_read():
    """An integration check against a real file rather than a synthetic one:
    the parser must handle the format this project actually writes."""
    own = pathlib.Path(__file__).resolve().parent.parent / "requirements.txt"
    if not own.is_file():                                        # pragma: no cover
        pytest.skip("requirements.txt is not present in this checkout")
    pins = sum(1 for line in own.read_text().splitlines()
               if "==" in line and not line.strip().startswith("#"))
    deps, _manifests, _found = collect_dependencies(
        make_zip({"requirements.txt": own.read_text()}))
    assert len(deps) >= 30, f"read {len(deps)} of {pins} pins"
    assert len(deps) == len({d.name for d in deps}), "each pin is one dependency"


def test_go_mod_names_the_builds_dependencies():
    gomod = "\n".join([
        "module example.com/app",
        "",
        "go 1.22",
        "",
        "require github.com/gin-gonic/gin v1.6.3",
        "",
        "require (",
        "    golang.org/x/text v0.3.3 // indirect",
        "    github.com/stretchr/testify v1.7.0",
        ")",
        "",
        "replace example.com/other => ../other",
    ]) + "\n"
    deps, manifests, _found = collect_dependencies(make_zip({"go.mod": gomod}))
    assert [(d.name, d.version, d.ecosystem) for d in deps] == [
        ("github.com/gin-gonic/gin", "v1.6.3", "Go"),
        ("golang.org/x/text", "v0.3.3", "Go"),
        ("github.com/stretchr/testify", "v1.7.0", "Go"),
    ]
    assert manifests == ["go.mod"]


def test_go_sum_alone_is_not_a_dependency_list():
    """go.sum is a checksum log of every module version the build EVER verified.
    Reading it reported retired software as installed; it is now reported as a
    file that cannot answer the question."""
    gosum = "\n".join([
        "github.com/example/retired v1.0.0 h1:aaa=",
        "github.com/example/current v2.0.0 h1:bbb=",
    ]) + "\n"
    deps, manifests, _found = collect_dependencies(make_zip({"go.sum": gosum}))
    assert deps == [], "go.sum is not the build's dependency list"
    assert manifests == []
    assert unusable_lockfiles(make_zip({"go.sum": gosum})) == ["go.sum"]


def test_a_workspace_resolved_package_is_read():
    """npm workspaces write `apps/web/node_modules/leftpad` for every package a
    workspace resolves itself. Reading only `node_modules/...` at the root
    skipped them without saying so."""
    workspace = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "root"},
        "apps/web": {"name": "web", "version": "1.0.0"},
        "apps/web/node_modules/leftpad": {"version": "1.3.0"},
        "node_modules/a/node_modules/nested": {"version": "9.9.9"},
        "node_modules/rootdep": {"version": "2.0.0"}}})
    deps, _manifests, _found = collect_dependencies(make_zip({"package-lock.json": workspace}))
    assert {d.name for d in deps} == {"leftpad", "nested", "rootdep"}, (
        "the workspace's own copy and a nested install are both installed packages")


def test_vendored_lockfiles_inside_node_modules_are_ignored():
    deps, manifests, _found = collect_dependencies(make_zip({
        "web/node_modules/some-package/package-lock.json": lockfile_v3()}))
    assert deps == []
    assert manifests == []


def test_the_root_lockfile_wins_over_a_nested_one():
    deps, manifests, _found = collect_dependencies(make_zip({
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/rootdep": {"version": "1.0.0"}}}),
        "apps/web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/nesteddep": {"version": "9.9.9"}}}),
    }))
    assert manifests[0] == "package-lock.json"
    assert {"rootdep", "nesteddep"} == {d.name for d in deps}


def test_the_same_version_twice_is_one_dependency():
    deps, _, _found = collect_dependencies(make_zip({
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/a": {"version": "1.0.0"}}}),
        "apps/api/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/a": {"version": "1.0.0"}}}),
    }))
    assert len(deps) == 1


def test_the_lookup_is_bounded_and_reports_what_the_cap_dropped():
    packages = {f"node_modules/pkg{i}": {"version": "1.0.0"}
                for i in range(MAX_DEPENDENCIES + 50)}
    deps, _, found = collect_dependencies(make_zip({
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": packages})}))
    assert len(deps) == MAX_DEPENDENCIES
    assert found == MAX_DEPENDENCIES + 50, (
        "the number seen is what makes the truncation visible to a reader")


def test_an_archive_with_no_lockfile_yields_nothing():
    deps, manifests, _found = collect_dependencies(make_zip({"src/app.py": "print(1)\n"}))
    assert (deps, manifests) == ([], [])


@pytest.mark.parametrize("raw,expected", [
    ("Django", "django"), ("zope.interface", "zope-interface"),
    ("my_package", "my-package"), ("a__b", "a-b"), (" A.B-c ", "a-b-c"),
])
def test_pypi_normalization(raw, expected):
    assert normalize_pypi(raw) == expected


def test_npm_dev_flag_is_carried_and_its_absence_means_production():
    """Measured on this repository's own lockfile: 170 of 327 entries carry
    dev: true, so the flag is common enough to change what a reader sees."""
    deps, _, _found = collect_dependencies(make_zip({"package-lock.json": json.dumps({
        "lockfileVersion": 3, "packages": {
            "node_modules/devdep": {"version": "1.0.0", "dev": True},
            "node_modules/proddep": {"version": "1.0.0"}}})}))
    by_name = {d.name: d for d in deps}
    assert by_name["devdep"].development is True
    assert by_name["proddep"].development is False


def test_formats_that_do_not_record_development_say_unknown_not_production():
    for entries in ({"requirements.txt": "django==2.0.0\n"},
                    {"go.mod": "module x\n\nrequire github.com/x/y v1.0.0\n"}):
        deps, _, _found = collect_dependencies(make_zip(entries))
        assert deps[0].development is None, (
            "silence about development is not a claim that it is production")


def test_poetry_category_dev_is_read_and_its_absence_is_unknown():
    poetry = "\n".join([
        "[[package]]", 'name = "pytest"', 'version = "7.0.0"', 'category = "dev"',
        "", "[[package]]", 'name = "requests"', 'version = "2.19.0"', "",
    ])
    deps, _, _found = collect_dependencies(make_zip({"poetry.lock": poetry}))
    by_name = {d.name: d for d in deps}
    assert by_name["pytest"].development is True
    assert by_name["requests"].development is None


def test_a_package_recorded_as_dev_and_production_counts_as_production():
    nested = json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/shared": {"version": "1.0.0"}}})
    root = json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/shared": {"version": "1.0.0", "dev": True}}})
    deps, _, _found = collect_dependencies(make_zip({
        "package-lock.json": root, "apps/api/package-lock.json": nested}))
    assert len(deps) == 1
    assert deps[0].development is False, (
        "it IS in the production install; the weaker claim must not win")
