"""Generated matcher invariants for an explicitly bounded version subset.

The oracles use integer positions, not the matcher's parser/comparator. Release
components are base-100 digits; prereleases are canonical alpha/beta/rc counters
(a/b/rc for PyPI). These properties make no claim about full PEP 440 support.
Derandomization makes failures reproducible for a fixed Hypothesis version;
normal shrinking still produces a small failing example.
"""
import io
import json
import zipfile

import pytest
from hypothesis import example, given, settings, strategies as st

from app.scan.cve_match import compare_versions, evaluate_advisory, match_archive


PROPERTY_SETTINGS = settings(max_examples=40, derandomize=True)
RELEASES = st.integers(min_value=0, max_value=999_999)
CVE_ID = "CVE-2026-12345"
GHSA_ID = "GHSA-2345-6789-cfgh"


def _release(position):
    return f"{position // 10_000}.{position // 100 % 100}.{position % 100}"


def _cve(ecosystem, lower, upper, *, inclusive=False, changes=None):
    row = {
        "version": lower,
        "lessThanOrEqual" if inclusive else "lessThan": upper,
        "versionType": "semver" if ecosystem == "npm" else "pep440",
        "status": "affected",
    }
    if changes is not None:
        row["changes"] = changes
    return {"id": CVE_ID, "default_status": "unaffected", "versions": [row]}


def _osv(lower, upper, closing="fixed"):
    return {
        "id": GHSA_ID, "source": "github-reviewed", "aliases": [CVE_ID],
        "osv_ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": lower}, {closing: upper},
        ]}],
        "osv_versions": [],
    }


def _scan(ecosystem, version, entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        if ecosystem == "npm":
            archive.writestr("package-lock.json", json.dumps({
                "lockfileVersion": 3,
                "packages": {"node_modules/widget": {"version": version}},
            }))
        else:
            archive.writestr("requirements.txt", f"widget=={version}\n")
    source = {
        "repository": "https://github.com/CVEProject/cvelistV5",
        "commit": "a" * 40, "generated_at": "2026-09-15T10:00:00Z",
    }
    catalog = {
        "schema_version": 2, "source": source,
        "sources": {
            "cvelist": source,
            "github-reviewed": {
                **source, "repository": "https://github.com/github/advisory-database",
                "commit": "b" * 40,
            },
        },
        "packages": {f"{ecosystem}:widget": entries},
    }
    return match_archive(stream.getvalue(), catalog)


@pytest.mark.parametrize("ecosystem", ["npm", "PyPI"])
@pytest.mark.parametrize("closing", ["fixed", "last_affected", "limit"])
@PROPERTY_SETTINGS
@given(lower=RELEASES, width=st.integers(min_value=1, max_value=30))
@example(lower=99, width=1)
@example(lower=9_999, width=1)
def test_generated_cve_and_osv_bounds_follow_integer_interval(ecosystem, closing, lower, width):
    upper = lower + width
    inclusive = closing == "last_affected"
    entries = [
        _cve(ecosystem, _release(lower), _release(upper), inclusive=inclusive),
        _osv(_release(lower), _release(upper), closing),
    ]
    # Every generated interval exercises both boundaries and their neighbours,
    # including carries between patch/minor/major components.
    for target in {max(0, lower - 1), lower, upper - 1, upper, upper + 1}:
        inside = lower <= target and (target <= upper if inclusive else target < upper)
        expected = "affected" if inside else "unaffected"
        for entry in entries:
            result = evaluate_advisory(_release(target), ecosystem, entry)
            assert result["status"] == expected, (target, entry)
            assert result["reason"] is None
            assert result["unresolved_ranges"] == 0


def _prerelease(core, position, ecosystem, *, equivalent=False):
    # The independent model's sequence is a0..a99, b0..b99, rc0..rc99,
    # final. The renderer only chooses each ecosystem's spelling.
    if position == 300:
        suffix = ""
    else:
        phase, counter = divmod(position, 100)
        if ecosystem == "npm":
            suffix = f"-{('alpha', 'beta', 'rc')[phase]}.{counter}"
        else:
            suffix = f"{('a', 'b', 'rc')[phase]}{counter}"
    if equivalent:
        return core + suffix + "+build.17" if ecosystem == "npm" else core + ".0.0" + suffix
    return core + suffix


@pytest.mark.parametrize("ecosystem", ["npm", "PyPI"])
@PROPERTY_SETTINGS
@given(core=RELEASES, left=st.integers(0, 300), right=st.integers(0, 300))
@example(core=100, left=9, right=10)
@example(core=100, left=299, right=300)
def test_prerelease_order_and_equivalent_spellings(ecosystem, core, left, right):
    expected = (left > right) - (left < right)
    release = _release(core)
    # Metadata in npm and zero padding in PyPI must not alter ordering.
    for equivalent in (False, True):
        version = _prerelease(release, left, ecosystem, equivalent=equivalent)
        other = _prerelease(release, right, ecosystem)
        assert compare_versions(version, other, ecosystem) == expected
        assert compare_versions(other, version, ecosystem) == -expected
        assert compare_versions(version, _prerelease(release, left, ecosystem), ecosystem) == 0


@pytest.mark.parametrize("ecosystem", ["npm", "PyPI"])
@PROPERTY_SETTINGS
@given(
    lower=RELEASES,
    offsets=st.lists(st.integers(1, 50), min_size=3, max_size=3, unique=True).map(sorted),
    order=st.permutations((0, 1, 2)),
)
def test_status_transitions_are_inclusive_and_independent_of_input_order(ecosystem, lower, offsets, order):
    points = [lower + offset for offset in offsets]
    upper = points[-1] + 1
    changes = [
        {"at": _release(point), "status": "unaffected" if index % 2 == 0 else "affected"}
        for index, point in enumerate(points)
    ]
    entry = _cve(ecosystem, _release(lower), _release(upper),
                 changes=[changes[index] for index in order])
    for target in {lower, upper, *(point - 1 for point in points), *points}:
        # Each transition flips the state, starting affected at the lower bound.
        inside = lower <= target < upper
        affected = inside and sum(point <= target for point in points) % 2 == 0
        result = evaluate_advisory(_release(target), ecosystem, entry)
        assert result["status"] == ("affected" if affected else "unaffected")
        assert result["reason"] is None
        assert result["unresolved_ranges"] == 0


def _unsupported_version(position, ecosystem):
    if ecosystem == "npm":
        return f"{position // 100}.{position % 100}"  # Missing SemVer patch.
    return _release(position) + ".post1"  # Outside the documented PyPI subset.


@pytest.mark.parametrize("ecosystem", ["npm", "PyPI"])
@PROPERTY_SETTINGS
@given(position=RELEASES)
def test_unsupported_bounds_and_installed_versions_cannot_become_unaffected(ecosystem, position):
    installed = _release(position + 1)
    unsupported = _unsupported_version(position, ecosystem)
    for entry, expected_reason in [
        (_cve(ecosystem, _release(0), unsupported), "unsupported_version"),
        (_osv("0", unsupported), "unsupported_osv_version"),
    ]:
        result = evaluate_advisory(installed, ecosystem, entry)
        assert result["status"] == "unknown"
        assert result["reason"] == expected_reason
        assert result["unresolved_ranges"] == 1
        assert result["matched_ranges"] == []

    for entry in [_cve(ecosystem, _release(0), installed), _osv("0", installed)]:
        result = evaluate_advisory(unsupported, ecosystem, entry)
        assert result["status"] == "unknown"
        assert result["reason"] == "unsupported_installed_version"
        assert result["unresolved_ranges"] == 1


@pytest.mark.parametrize("ecosystem", ["npm", "PyPI"])
@pytest.mark.parametrize("uncertainty", ["unsupported", "disagreement"])
@PROPERTY_SETTINGS
@given(position=RELEASES, known_status=st.sampled_from(["affected", "unaffected"]))
def test_source_uncertainty_and_evidence_survive_source_reordering(ecosystem, uncertainty, position, known_status):
    version = _release(position)
    cna = {"id": CVE_ID, "default_status": "unaffected", "versions": [
        {"version": version, "status": known_status},
    ]}
    if uncertainty == "unsupported":
        reviewed = _osv("0", _unsupported_version(position, ecosystem))
        ghsa_status, ghsa_reason = "unknown", "unsupported_osv_version"
        reason = "incomplete_advisory_sources"
    else:
        reviewed = _osv("0", _release(position if known_status == "affected" else position + 1))
        ghsa_status = "unaffected" if known_status == "affected" else "affected"
        ghsa_reason = None
        reason = "conflicting_advisory_sources"

    for entries in ([cna, reviewed], [reviewed, cna]):
        result = _scan(ecosystem, version, entries)
        assert result["findings"] == []
        coverage = result["coverage"]
        assert coverage["status"] == "partial"
        assert coverage["status_counts"] == {
            "affected": 0, "unaffected": 0, "unknown": 1, "not_in_catalog": 0,
        }
        assert coverage["unknown_reason_counts"] == {reason: 1}
        detail, = coverage["details"]
        assert detail["reason"] == reason
        assert detail["assessments_truncated"] == 0
        assert sorted(detail["assessments"], key=lambda item: item["source"]) == [
            {"source": "cvelist", "advisory": CVE_ID, "status": known_status, "reason": None},
            {"source": "github-reviewed", "advisory": GHSA_ID, "status": ghsa_status, "reason": ghsa_reason},
        ]
