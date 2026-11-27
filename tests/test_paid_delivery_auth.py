"""Actual envelope/binding and worker checks; no live provider credentials."""
import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet

import app.main as main
from app.services.deploypack import paid_delivery_auth as auth
from app.services.deploypack.delivery import PullRequestResult
from app.services.deploypack.delivery_auth import DeliveryAuthorizationError
from tests.test_fixpack_process_endpoint import _review_job_setup, _review_zip

BINDING = dict(provider="bank_transfer", external_ref="fixture-reference",
               audit_id="a1", repo_full_name="acme/app")
TOKEN = "github-pat-paid-fixture"


@pytest.fixture
def cipher(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("FIXPACK_DELIVERY_ENCRYPTION_KEY", key.decode())
    return Fernet(key)


def test_ciphertext_and_binding(cipher):
    encrypted = auth.seal_paid_grant(TOKEN, **BINDING)
    assert TOKEN not in encrypted
    assert auth.open_paid_grant(encrypted, **BINDING) == TOKEN
    assert auth.open_paid_grant(encrypted, **{**BINDING, "repo_full_name": "ACME/APP"}) == TOKEN


@pytest.mark.parametrize("field,value", [
    ("provider", "yookassa"), ("external_ref", "another-order"),
    ("audit_id", "another-audit"), ("repo_full_name", "other/app"),
])
def test_cannot_move_envelope_between_orders_or_repositories(cipher, field, value):
    encrypted = auth.seal_paid_grant(TOKEN, **BINDING)
    with pytest.raises(DeliveryAuthorizationError) as error:
        auth.open_paid_grant(encrypted, **{**BINDING, field: value})
    assert error.value.status_code == 401
    assert TOKEN not in str(error.value)


@pytest.mark.parametrize("kind", ["expired", "modified", "wrong-key", "missing"])
def test_expired_corrupt_or_missing_grants_refuse(cipher, monkeypatch, kind):
    encrypted = auth.seal_paid_grant(TOKEN, **BINDING)
    if kind == "expired":
        data = cipher.decrypt(encrypted.encode())
        encrypted = cipher.encrypt_at_time(data, int(time.time()) - auth.GRANT_TTL_SECONDS - 1).decode()
    elif kind == "modified":
        encrypted = encrypted[:-10] + "corrupt"
    elif kind == "wrong-key":
        monkeypatch.setenv("FIXPACK_DELIVERY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    else:
        encrypted = None
    with pytest.raises(DeliveryAuthorizationError) as error:
        auth.open_paid_grant(encrypted, **BINDING)
    assert error.value.status_code == 401


@pytest.mark.parametrize("key", ["", "bad", "кириллица"])
def test_key_misconfiguration_refuses_before_invoice(monkeypatch, key):
    monkeypatch.setenv("FIXPACK_DELIVERY_ENCRYPTION_KEY", key)
    with pytest.raises(DeliveryAuthorizationError) as error:
        auth.seal_paid_grant(TOKEN, **BINDING)
    assert error.value.status_code == 503
    assert key not in str(error.value) if key else True


@pytest.mark.parametrize("scenario", [
    "deliver", "missing", "revoke", "swap", "outage", "settling", "settled_between_reads",
])
def test_real_worker_reloads_and_rechecks_invoice_authority(cipher, monkeypatch, scenario):
    audits, jobs = _review_job_setup()
    job = {"id": "j1", "audit_id": "a1", "status": "running"}
    row = {**BINDING, "encrypted_grant": auth.seal_paid_grant(TOKEN, **BINDING)}
    calls = []
    opened = []
    store = SimpleNamespace(
        get_for_job=AsyncMock(return_value=row),
        funding_pending=AsyncMock(return_value=False),
        await_authorization=AsyncMock(), clear_for_job=AsyncMock(),
    )
    monkeypatch.setattr(auth, "get_paid_delivery_store", lambda: store)
    monkeypatch.setattr(main, "get_paid_delivery_store", lambda: store)
    monkeypatch.setenv("GITHUB_PR_TOKEN", "operator-must-not-write")

    def authorize(owner, repo, token):
        assert (owner, repo, token) == ("acme", "app", TOKEN)
        calls.append(token)
        if scenario == "revoke" and len(calls) == 2:
            raise DeliveryAuthorizationError(403, "repository_write_access_required")
        if scenario == "outage":
            raise DeliveryAuthorizationError(502, "github_authorization_unavailable")

    def fetch(owner, repo):
        if scenario == "swap":
            # A modified payment/audit association after generation cannot be used.
            store.get_for_job.return_value = {**row, "audit_id": "someone-else"}
        return _review_zip()

    def opener(*args, **kwargs):
        opened.append(kwargs["token"])
        return PullRequestResult("https://github.com/acme/app/pull/9", "fixture")

    if scenario == "settling":
        store.get_for_job.return_value = None
        store.funding_pending.return_value = True
        def fetch(*args):
            pytest.fail("work reached repository fetch before settlement")
    if scenario == "settled_between_reads":
        store.get_for_job.side_effect = [None, row, row]
    if scenario == "missing":
        store.get_for_job.return_value = None
        def fetch(*args):
            pytest.fail("unfunded/unauthorized work reached repository fetch")

    monkeypatch.setattr(auth, "authorize_repository_delivery", authorize)
    monkeypatch.setattr(main, "_resolve_pr_token", AsyncMock(side_effect=AssertionError("server authority")))
    monkeypatch.setattr(main, "run_semantic_check", lambda *a, **k: SimpleNamespace(
        verification_unavailable=False, regression=False, blocked=False, pr_note=None))
    monkeypatch.setattr(main, "run_proof_stage", AsyncMock(return_value=None))
    monkeypatch.setattr(main, "decide_proof_gate", lambda report: "pass")
    monkeypatch.setattr(main, "_deep_review_section", AsyncMock(return_value="Fixture review"))
    outcome = asyncio.run(main._process_one_paid_job(
        job, audit_repo=audits, fixpack_repo=jobs,
        fix_outcome_repo=SimpleNamespace(record=AsyncMock()),
        repo_fetcher=fetch, pr_opener=opener, llm_client=None,
    ))
    if scenario in ("deliver", "settled_between_reads"):
        assert outcome == "delivered"
        assert opened == [TOKEN] and len(calls) == 2
        store.clear_for_job.assert_awaited_once_with("j1")
    elif scenario in ("outage", "settling"):
        assert outcome == "authorization_deferred"
        assert jobs.released == ["j1"] and opened == []
        store.await_authorization.assert_not_awaited()
    else:
        assert outcome == "awaiting_authorization" and opened == []
        store.await_authorization.assert_awaited_once()
    assert TOKEN not in json.dumps(jobs.details)
