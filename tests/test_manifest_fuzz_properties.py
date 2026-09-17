"""Bounded parser fuzzing keeps independent resolved pins and honest gaps.

Guaranteed-invalid/ambiguous manifests, arbitrary bytes and valid formatting
perturbations have different oracles. A random byte string is not assumed to
be invalid: an empty requirements file or a comment can be legitimate.
Inputs stay below file/count/parser budgets; no uploaded code is executed.
"""
import io
import json
import zipfile

import pytest
from hypothesis import given, settings, strategies as st
import yaml

from app.sca.lockfiles import collect_dependency_inventory
from app.scan.cve_match import match_archive


MANIFESTS = ("package-lock.json", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "requirements.txt")
PROPERTY_SETTINGS = settings(max_examples=24, derandomize=True)
NOISE = st.text(alphabet="abcxyz0123456789", max_size=12)
GOOD_MANIFEST = "z-good/requirements.txt"
GOOD_PIN = "fuzz-control==1.2.3\n"


def _archive(files, *, reverse=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, body in list(files.items())[::(-1 if reverse else 1)]:
            archive.writestr(name, body)
    return stream.getvalue()


def _catalog():
    return {
        "schema_version": 1,
        "source": {"repository": "https://github.com/CVEProject/cvelistV5",
                   "commit": "a" * 40, "generated_at": "2026-09-17T10:00:00Z"},
        "packages": {key: [{
            "id": "CVE-2026-12345", "default_status": "unaffected", "versions": [{
                "version": "1.0.0", "lessThan": "2.0.0", "status": "affected",
                "versionType": "semver" if key.startswith("npm:") else "pep440",
            }],
        }] for key in ("PyPI:fuzz-control", "PyPI:fuzz-widget", "npm:fuzz-widget")},
    }


def _inspect(files):
    data = _archive(files)
    reversed_data = _archive(files, reverse=True)
    inventory = collect_dependency_inventory(data)
    result = match_archive(data, _catalog())
    # Archive insertion order must not change which manifests or pins survive.
    assert collect_dependency_inventory(reversed_data) == inventory
    assert match_archive(reversed_data, _catalog()) == result
    assert set(inventory.manifests) == set(files)
    controls = [dep for dep in inventory.dependencies if (
        dep.ecosystem, dep.name, dep.version
    ) == ("PyPI", "fuzz-control", "1.2.3")]
    assert len(controls) == 1
    assert any(item.manifest == GOOD_MANIFEST and item.line == 1 for item in controls[0].occurrences)
    evidence = [finding["claim_evidence"] for finding in result["findings"]
                if (finding["claim_evidence"]["ecosystem"], finding["claim_evidence"]["package"],
                    finding["claim_evidence"]["installed_version"]) == ("PyPI", "fuzz-control", "1.2.3")]
    assert len(evidence) == 1
    assert evidence[0]["installed_version"] == "1.2.3"
    assert evidence[0]["occurrences_recorded"] is True
    assert {"manifest": GOOD_MANIFEST, "line": 1, "direct": False,
            "dependency_scope": "unknown", "dependency_groups": []} in evidence[0]["occurrences"]
    coverage = result["coverage"]
    assert coverage["dependencies_found"] == inventory.found
    assert coverage["dependencies_checked"] == inventory.found
    assert coverage["incomplete_manifests"] == inventory.incomplete_manifests
    assert coverage["inventory_truncated"] == coverage["evaluations_truncated"] == 0
    return inventory, result


def _valid_source(manifest, version, *, pretty=False, reverse_keys=False, comments=0, crlf=False):
    if manifest == "package-lock.json":
        values = {"lockfileVersion": 3, "note": "fuzz-metadata", "packages": {
            "node_modules/fuzz-widget": {"version": version},
        }}
        if reverse_keys:
            values = dict(reversed(list(values.items())))
        text = json.dumps(values, indent=2 if pretty else None)
    elif manifest == "pnpm-lock.yaml":
        values = {
            "lockfileVersion": "9.0",
            "importers": {".": {"dependencies": {"fuzz-widget": {"version": version}}}},
            "packages": {f"fuzz-widget@{version}": {"resolution": {"integrity": "sha512-synthetic"}}},
            "snapshots": {f"fuzz-widget@{version}": {}},
        }
        text = yaml.safe_dump(values, sort_keys=reverse_keys, default_flow_style=pretty)
    elif manifest in {"poetry.lock", "uv.lock"}:
        fields = ['name = "fuzz-widget"', f'version = "{version}"']
        if manifest == "uv.lock":
            fields.append('source = { registry = "https://pypi.org/simple" }')
        if reverse_keys:
            fields.reverse()
        text = ("version = 1\n" if manifest == "uv.lock" else "") + "[[package]]\n"
        text += "\n".join(fields) + "\n"
        if pretty:
            text = text.replace(" = ", "\t=\t")
    else:
        text = f"fuzz-widget=={version}\n"
        if pretty:
            text = " \t" + text.rstrip() + "  # exact pin\n"
    if manifest != "package-lock.json":
        text = "# formatting-only comment\n" * comments + text
    return text.replace("\n", "\r\n") if crlf else text


def _bad_sources(manifest):
    if manifest == "package-lock.json":
        return st.one_of(
            NOISE.map(lambda noise: '{"broken": [' + noise),
            st.sampled_from([
                '[]', '{"packages": [], "dependencies": {}}',
                '{"packages": {}, "packages": {"node_modules/ghost": {"version": "1.0.0"}}}',
                '{"packages": {"node_modules/ghost": {"version": "1.0.0", "version": "1.1.0"}}}',
                '{"packages": {}, "metadata": NaN}',
                '{"packages": {}, "metadata": Infinity}',
            ]),
        )
    if manifest == "pnpm-lock.yaml":
        return st.one_of(
            NOISE.map(lambda noise: "lockfileVersion: '9.0'\nimporters: [" + noise),
            st.sampled_from([
                "lockfileVersion: '9.0'\nimporters: []\n",
                "lockfileVersion: '9.0'\nimporters: {}\npackages: 0\n",
                "lockfileVersion: '9.0'\nlockfileVersion: '9.0'\nimporters: {}\n",
                "lockfileVersion: '9.0'\nimporters: &value {}\nsnapshots: *value\n",
            ]),
        )
    if manifest in {"poetry.lock", "uv.lock"}:
        prefix = "version = 1\n" if manifest == "uv.lock" else ""
        broken_names = st.text(alphabet="._-", min_size=1, max_size=6).map(
            lambda name: prefix + f'[[package]]\nname = "{name}"\nversion = "1.2.3"\n')
        return st.one_of(
            NOISE.map(lambda noise: prefix + 'package = ["' + noise),
            st.sampled_from([prefix + "package = 7\n", prefix + "package = [1, 2]\n"]),
            broken_names,
            st.integers(0, 9).map(lambda number: prefix +
                                 f'[[package]]\nname = "ghost"\nversion = ">={number}"\n'),
        )
    # A bare '[' cannot name a requirement; a range is not a resolved pin.
    # Avoid comments/empty files: those can legitimately have no dependencies.
    return st.one_of(NOISE.map(lambda noise: "[" + noise + "\n"),
                     st.integers(0, 99).map(lambda number: f"ghost>={number}\n"),
                     NOISE.map(lambda noise: "-r missing-" + noise + ".txt\n"))


@pytest.mark.parametrize("manifest", MANIFESTS)
@PROPERTY_SETTINGS
@given(data=st.data())
def test_guaranteed_bad_manifest_is_a_gap_and_preserves_independent_positive(manifest, data):
    body = data.draw(_bad_sources(manifest), label="invalid-or-ambiguous-manifest")
    inventory, result = _inspect({manifest: body, GOOD_MANIFEST: GOOD_PIN})
    assert manifest in inventory.incomplete_manifests
    assert GOOD_MANIFEST not in inventory.incomplete_manifests
    assert inventory.found == 1
    assert result["coverage"]["status"] == "partial"
    assert result["coverage"]["status_counts"] == {
        "affected": 1, "unaffected": 0, "unknown": 0, "not_in_catalog": 0,
    }


@pytest.mark.parametrize("manifest", MANIFESTS)
@PROPERTY_SETTINGS
@given(invalid=st.integers(min_value=0x80, max_value=0xBF), marker=NOISE)
def test_invalid_utf8_inside_otherwise_valid_metadata_cannot_disappear(manifest, invalid, marker):
    valid = _valid_source(manifest, "1.2.3").encode()
    if manifest == "package-lock.json":
        corrupted = valid.replace(b"fuzz-metadata", marker.encode() + bytes([invalid]))
    else:
        corrupted = b"# " + marker.encode() + bytes([invalid]) + b"\n" + valid
    inventory, result = _inspect({manifest: corrupted, GOOD_MANIFEST: GOOD_PIN})
    assert manifest in inventory.incomplete_manifests
    assert inventory.found == 1
    assert result["coverage"]["status"] == "partial"
    assert len(result["findings"]) == 1


@pytest.mark.parametrize("manifest", MANIFESTS)
@PROPERTY_SETTINGS
@given(body=st.binary(max_size=48))
def test_arbitrary_small_bytes_never_discard_the_independent_positive(manifest, body):
    # No blanket invalidity assertion: some generated byte strings are valid.
    _inspect({manifest: body, GOOD_MANIFEST: GOOD_PIN})


@pytest.mark.parametrize("manifest", MANIFESTS)
@PROPERTY_SETTINGS
@given(minor=st.integers(0, 20), patch=st.integers(0, 20), pretty=st.booleans(),
       reverse_keys=st.booleans(), comments=st.integers(0, 3), crlf=st.booleans())
def test_valid_formatting_perturbations_preserve_exact_pins_and_coverage(
    manifest, minor, patch, pretty, reverse_keys, comments, crlf,
):
    version = f"1.{minor}.{patch}"
    body = _valid_source(manifest, version, pretty=pretty, reverse_keys=reverse_keys,
                         comments=comments, crlf=crlf)
    inventory, result = _inspect({manifest: body, GOOD_MANIFEST: GOOD_PIN})
    ecosystem = "npm" if manifest in {"package-lock.json", "pnpm-lock.yaml"} else "PyPI"
    assert {(dep.ecosystem, dep.name, dep.version) for dep in inventory.dependencies} == {
        (ecosystem, "fuzz-widget", version), ("PyPI", "fuzz-control", "1.2.3"),
    }
    widget, = [dep for dep in inventory.dependencies if dep.name == "fuzz-widget"]
    assert widget.manifest == manifest
    assert widget.line == (comments + 1 if manifest == "requirements.txt" else 0)
    assert inventory.incomplete_manifests == {}
    assert inventory.found == 2
    assert result["coverage"]["advisory_evaluations"] == 2
    assert result["coverage"]["status_counts"] == {
        "affected": 2, "unaffected": 0, "unknown": 0, "not_in_catalog": 0,
    }
