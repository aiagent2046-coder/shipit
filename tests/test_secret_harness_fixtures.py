"""Keep local harness credentials runnable without hiding real script leaks."""

import io
import zipfile
from dataclasses import asdict
from pathlib import Path

import pytest

from app.fixpack.generate import build_fixpack_plan, has_auto_fixable_findings
from app.proof.templates.secrets_leak import run as prove_secrets
from app.proof.workspace import apply_plan_to_zip
from app.scan.secrets import is_non_production_path, scan_secrets


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for path, body in files.items():
            archive.writestr(f"owner-repo-deadbeef/{path}", body)
    return buf.getvalue()


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize(("path", "value"), [
    ("scripts/e2e_proof_bundle_probe.py", "e2e-not-a-real-password"),
    ("scripts/e2e_proof_bundle_probe.py", "e2e-bundle-stand-jwt-secret-not-a-real-one-xxxxxxxx"),
    ("scripts/e2e_proof_rls_probe.py", "e2e-not-a-real-password"),
    ("scripts/smoke_verify_reap_endpoint.py", "smoke-test-reap-token"),
])
def test_labelled_local_harness_value_is_reported_but_not_rewritten(path, value, quote):
    archive = _zip({path: f"SECRET = {quote}{value}{quote}\n"})
    findings = scan_secrets(io.BytesIO(archive))
    assert findings
    assert all(f.context == "test_fixture" and f.severity == "low" for f in findings)
    assert value not in repr(findings)
    assert not has_auto_fixable_findings([asdict(f) for f in findings])
    assert not prove_secrets(archive).success

    # A saved audit predating the new classification must not edit this
    # literal merely because its old context says it is production code.
    stale = [{**asdict(f), "context": None, "severity": "high"} for f in findings]
    assert has_auto_fixable_findings(stale)
    plan = build_fixpack_plan(archive, stale)
    assert not plan.has_changes
    assert len(plan.skipped) == len(stale)
    assert all("test_fixture on fresh scan" in f.reason for f in plan.skipped)


@pytest.mark.parametrize(("path", "value", "variable"), [
    ("scripts/smoke_verify_reap_endpoint.py", "K7yB92q8Lm3pV6rX", "TOKEN"),
    ("scripts/e2e_proof_bundle_probe.py", "K7yB92q8Lm3pV6rX", "TEST_ONLY_SECRET"),
    ("scripts/smoke_verify_reap_endpoint.py", "K7fake92q8Lm3pV6rX", "TOKEN"),
    ("scripts/smoke_verify_reap_endpoint.py", "smoke-deployment-token", "TOKEN"),
    ("scripts/deploy.py", "smoke-test-reap-token", "TOKEN"),
    ("app/smoke_verify_reap_endpoint.py", "smoke-test-reap-token", "TOKEN"),
    ("src/config.py", "e2e-not-a-real-password", "TEST_PASSWORD"),
    ("src/config.py", "smoke-test-reap-token", "TEST_TOKEN"),
    ("migrations/scripts/e2e_seed.py", "e2e-not-a-real-password", "PASSWORD"),
])
def test_path_or_test_word_alone_never_downgrades_a_production_secret(path, value, variable):
    archive = _zip({path: f'{variable} = "{value}"\n'})
    findings = scan_secrets(io.BytesIO(archive))
    assert findings
    assert all(f.context is None and f.severity == "high" for f in findings)
    assert prove_secrets(archive).success


@pytest.mark.parametrize("path", [
    "scripts/e2e_proof_bundle_probe.py",
    "scripts/smoke_verify_reap_endpoint.py",
])
@pytest.mark.parametrize(("value", "rule"), [
    ("ghp_" + "a" * 36, "github-pat"),
    ("sk_" + "live_" + "B" * 24, "stripe-live-key"),
    ("sk-ant-api03-" + "test-only-" + "C" * 24, "anthropic-api-key"),
    ("smoke-test-ghp_" + "d" * 36, "github-pat"),
    ("postgres" + "://user:smoke-test-password@db.production.example/app",
     "connection-string-password"),
])
def test_provider_credentials_in_harness_stay_actionable_even_with_test_markers(path, value, rule):
    archive = _zip({path: f'SECRET = "{value}"\n'})
    findings = scan_secrets(io.BytesIO(archive))
    hit = next(f for f in findings if f.rule_id == rule)
    assert hit.severity == "critical" and hit.context is None
    assert all(f.context is None for f in findings)
    assert prove_secrets(archive).success
    assert not is_non_production_path(path)


def test_actual_repository_harnesses_survive_a_fixpack_from_an_old_audit():
    root = Path(__file__).resolve().parents[1]
    paths = [
        "scripts/e2e_proof_bundle_probe.py",
        "scripts/e2e_proof_rls_probe.py",
        "scripts/smoke_verify_reap_endpoint.py",
    ]
    archive = _zip({path: (root / path).read_text() for path in paths})
    findings = scan_secrets(io.BytesIO(archive))
    fixtures = [f for f in findings if f.context == "test_fixture"]
    assert len(fixtures) == 4
    assert not prove_secrets(archive).success
    stale = [{**asdict(f), "context": None, "severity": "high"} for f in fixtures]
    plan = build_fixpack_plan(archive, stale)
    assert not plan.has_changes
    assert len(plan.skipped) == 4


def test_genuine_secret_beside_harness_fixture_is_still_fixed():
    value = "ghp_" + "e" * 36
    path = "scripts/smoke_verify_reap_endpoint.py"
    archive = _zip({path: 'TOKEN = "smoke-test-reap-token"\n' + f'KEY = "{value}"\n'})
    findings = [asdict(f) for f in scan_secrets(io.BytesIO(archive))]
    plan = build_fixpack_plan(archive, findings)
    assert plan.has_changes
    assert value not in plan.files[path]
    assert 'TOKEN = "smoke-test-reap-token"' in plan.files[path]
    assert prove_secrets(archive).success
    assert not prove_secrets(apply_plan_to_zip(archive, plan.files, plan.deletions)).success
