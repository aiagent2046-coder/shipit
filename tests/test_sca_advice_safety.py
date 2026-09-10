"""Advice must not turn advisory boundaries into unverified upgrade guarantees."""
from app.sca.lockfiles import Dependency
from app.sca.stage import _advisories, build_finding


def package(*, development=None):
    return Dependency("npm", "example", "1.0.0", "package-lock.json",
                      development=development)


def record(identifier, *, events=None, range_type="SEMVER", affected=None):
    return {
        "id": identifier,
        "database_specific": {"severity": "HIGH"},
        "affected": affected if affected is not None else [{
            "package": {"ecosystem": "npm", "name": "example"},
            "ranges": [{"type": range_type, "events": events or []}],
        }],
    }


def finding(records, *, missing=(), development=None):
    dependency = package(development=development)
    return build_finding(dependency, _advisories(dependency, records, missing))


def test_prereleases_and_reintroduced_vulnerabilities_do_not_define_a_safe_target():
    result = finding([
        record("OSV-first", events=[
            {"introduced": "0"}, {"fixed": "2.0.0rc1"},
            {"introduced": "2.0.0"}, {"fixed": "2.0.1"},
        ]),
        record("OSV-second", events=[
            {"introduced": "0"}, {"fixed": "2.0.0rc2"},
        ]),
    ])
    assert "OSV-first: fixed versions recorded by the database: 2.0.0rc1, 2.0.1" in result.fix_hint
    assert "OSV-second: fixed versions recorded by the database: 2.0.0rc2" in result.fix_hint
    assert "common safe upgrade target was not verified" in result.fix_hint
    assert "Upgrade to" not in result.fix_hint
    assert "or later" not in result.fix_hint


def test_alternative_maintenance_lines_remain_source_facts_in_source_order():
    result = finding([record("OSV-lines", events=[
        {"introduced": "3.0.0"}, {"fixed": "3.2.1"},
        {"introduced": "2.0.0"}, {"fixed": "2.9.8"},
    ])])
    assert "fixed versions recorded by the database: 3.2.1, 2.9.8" in result.fix_hint
    assert "earlier fixes" not in result.fix_hint
    assert "do not clear every advisory" not in result.fix_hint


def test_missing_fix_and_missing_details_are_distinct_unknowns():
    result = finding([
        record("OSV-fixed", events=[{"fixed": "1.2.0"}]),
        record("OSV-no-fix", events=[{"introduced": "0"}]),
    ], missing=("OSV-unavailable",))
    assert "OSV-fixed: fixed versions recorded by the database: 1.2.0" in result.fix_hint
    assert "OSV-no-fix: no fixed version recorded" in result.fix_hint
    assert "OSV-unavailable: details unavailable; fixed versions unknown" in result.fix_hint
    assert "clears every advisory" not in result.fix_hint


def test_git_fixed_commit_is_not_offered_as_a_package_version():
    result = finding([record("OSV-git", range_type="GIT", events=[
        {"fixed": "abcdef0123456789abcdef0123456789abcdef01"},
    ])])
    assert "no fixed version recorded" in result.fix_hint
    assert "abcdef0123456789" not in result.fix_hint


def test_other_packages_and_unattributed_ranges_are_not_fix_advice():
    result = finding([record("OSV-mixed", affected=[
        {"package": {"ecosystem": "npm", "name": "different"},
         "ranges": [{"type": "SEMVER", "events": [{"fixed": "99.0.0"}]}]},
        {"ranges": [{"type": "SEMVER", "events": [{"fixed": "88.0.0"}]}]},
    ])])
    assert "no fixed version recorded" in result.fix_hint
    assert "99.0.0" not in result.fix_hint
    assert "88.0.0" not in result.fix_hint


def test_truncated_version_facts_and_advisories_are_disclosed():
    records = [record(f"OSV-{index}", events=[
        {"fixed": f"1.{minor}.0"} for minor in range(6)
    ]) for index in range(6)]
    result = finding(records)
    assert "and 2 more fixed versions" in result.fix_hint
    assert "Fix details for 2 additional advisories are not shown here" in result.fix_hint
    assert "Review every advisory's affected ranges" in result.fix_hint


def test_dev_flag_does_not_establish_runtime_or_build_reachability():
    result = finding([record("OSV-dev", events=[{"fixed": "1.2.0"}])], development=True)
    assert "marks this as a development dependency" in result.explanation
    assert "its use in builds or the deployed application was not checked" in result.explanation
    assert "does not reach the running application" not in result.explanation
