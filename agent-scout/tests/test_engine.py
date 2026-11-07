"""Engine adapter tests: synthetic manifests -> drydock engine -> triage rollup.

Fixture policy: use real advisories from the pinned catalog so the test
proves the whole consumption path, not a mock. The KEV case is langflow
1.2.0 (multiple CISA KEV-listed advisories).
"""
from __future__ import annotations

import json

import pytest

from scout.engine import Engine, artifact_fingerprint, rank


@pytest.fixture(scope="module")
def engine() -> Engine:
    return Engine()


def make_lockfile(deps: dict[str, str]) -> bytes:
    packages = {"": {"name": "demo", "dependencies": dict(deps)}}
    for name, version in deps.items():
        packages[f"node_modules/{name}"] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        }
    return json.dumps(
        {"name": "demo", "lockfileVersion": 3, "packages": packages}
    ).encode()


def make_requirements(deps: dict[str, str]) -> bytes:
    return ("\n".join(f"{name}=={version}" for name, version in deps.items()) + "\n").encode()


def test_npm_advisory_match(engine: Engine) -> None:
    result = engine.scan_files(
        {"package-lock.json": make_lockfile({"lodash": "4.17.15"})},
        target="fixture/npm",
    )
    assert result.findings, "known-vulnerable lodash version must match advisories"
    assert result.coverage["dependencies_checked"] == 1
    titles = " ".join(f["title"] for f in result.findings)
    assert "lodash 4.17.15" in titles
    assert all(f["claim_evidence"]["installed_version"] == "4.17.15"
               for f in result.findings)


def test_kev_listing_raises_critical(engine: Engine) -> None:
    result = engine.scan_files(
        {"requirements.txt": make_requirements({"langflow": "1.2.0"})},
        target="fixture/pypi",
    )
    kev = result.kev_listed
    assert kev, "langflow 1.2.0 carries CISA KEV-listed advisories in the pinned snapshot"
    top = kev[0]
    assert top["claim_evidence"]["exploitation"]["status"] == "listed"
    assert top["claim_evidence"]["exploitation"]["source"] == "cisa-kev"
    assert all("(CISA KEV)" in f["title"] for f in kev)
    assert all(f["claim_evidence"]["advisory_ids"] for f in kev)
    # product rule: KEV escalation is visible in the rollup
    assert rank(result.findings)[0] is top
    assert result.critical


def test_absence_is_not_safety(engine: Engine) -> None:
    result = engine.scan_files(
        {"package-lock.json": make_lockfile({"left-pad": "1.3.0"})},
        target="fixture/clean",
    )
    text = " ".join(result.limitations).lower()
    assert "do not establish" in text or "not establish" in text
    # engine records its own epistemic limits in every result
    assert result.limitations


def test_fingerprint_stable(engine: Engine) -> None:
    files = {"package-lock.json": make_lockfile({"lodash": "4.17.15"})}
    assert artifact_fingerprint(files) == artifact_fingerprint(dict(files))
    other = {"package-lock.json": make_lockfile({"lodash": "4.17.20"})}
    assert artifact_fingerprint(files) != artifact_fingerprint(other)
