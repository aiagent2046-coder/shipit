"""Renewal needs the audit capability, its settled order, and fresh GitHub access."""
from __future__ import annotations

import uuid

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.main import app, get_audit_repo, get_fixpack_repo, get_payment_repo
from app.routes import billing as paid_delivery
from app.services.billing import bank_transfer, yookassa
from app.services.deploypack import paid_delivery_auth
from app.services.deploypack.delivery_auth import DeliveryAuthorizationError
from app.services.deploypack.paid_delivery_auth import open_paid_grant

AUDIT_ID = "11111111-1111-4111-8111-111111111111"
AUDIT_TOKEN = "a" * 32
GITHUB_TOKEN = "fixture-renewal-github-token"
REFERENCE = "DRY-ABC123"


class AuditStore:
    async def get_authorized(self, audit_id, token):
        if audit_id == AUDIT_ID and token == AUDIT_TOKEN:
            return {"id": AUDIT_ID, "repo_url": "https://github.com/acme/widget"}
        return None


class PaymentStore:
    def __init__(self):
        self.rows = {}
        self.lookups = []

    async def get_by_external_ref(self, provider, reference):
        self.lookups.append((provider, reference))
        return self.rows.get((provider, reference))

    def add(self, provider, **changes):
        row = {
            "id": str(uuid.uuid4()), "provider": provider,
            "external_ref": REFERENCE, "audit_id": AUDIT_ID,
            "status": "completed", "product": "fixpack",
            **changes,
        }
        self.rows[(provider, row["external_ref"])] = row
        return row


class GrantStore:
    def __init__(self):
        self.attempts = []
        self.saved = []
        self.allow_replace = True
        self.funding = None
        self.reads = []

    async def replace_for_payment(self, payment_id, encrypted):
        self.attempts.append((payment_id, encrypted))
        if self.allow_replace:
            self.saved.append((payment_id, encrypted))
            return True
        return False

    async def get_for_job(self, job_id):
        self.reads.append(job_id)
        return self.funding


@pytest.fixture
def renewal(monkeypatch):
    monkeypatch.setenv("FIXPACK_DELIVERY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    payments, grants = PaymentStore(), GrantStore()
    github_checks = []

    def authorize(owner, repo, token):
        github_checks.append((owner, repo, token))

    monkeypatch.setattr(paid_delivery_auth, "authorize_repository_delivery", authorize)
    app.dependency_overrides[get_audit_repo] = lambda: AuditStore()
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[paid_delivery.get_paid_delivery_store] = lambda: grants
    # The read endpoint resolves this helper inside its handler.
    monkeypatch.setattr(paid_delivery_auth, "get_paid_delivery_store", lambda: grants)
    with TestClient(app) as client:
        yield client, payments, grants, github_checks
    for dependency in (
        get_audit_repo, get_payment_repo, get_fixpack_repo,
        paid_delivery.get_paid_delivery_store,
    ):
        app.dependency_overrides.pop(dependency, None)


def _renew(client, *, reference=REFERENCE, audit_token=AUDIT_TOKEN, github_token=GITHUB_TOKEN):
    return client.post(
        f"/v1/audits/{AUDIT_ID}/fixpack/delivery-authorization",
        json={"reference": reference, "audit_token": audit_token},
        headers={"X-GitHub-Token": github_token} if github_token is not None else {},
    )


@pytest.mark.parametrize("audit_token", [None, "", "wrong-audit-token", "b" * 32])
def test_audit_capability_is_required_before_order_lookup(renewal, audit_token):
    client, payments, grants, checks = renewal
    payments.add(bank_transfer.PROVIDER)
    response = _renew(client, audit_token=audit_token)
    assert response.status_code == (422 if audit_token is None else 404)
    assert not payments.lookups
    assert not grants.attempts
    assert not checks


def test_omitted_audit_token_is_rejected(renewal):
    client, payments, grants, checks = renewal
    response = client.post(
        f"/v1/audits/{AUDIT_ID}/fixpack/delivery-authorization",
        json={"reference": REFERENCE}, headers={"X-GitHub-Token": GITHUB_TOKEN},
    )
    assert response.status_code == 422
    assert not payments.lookups and not grants.attempts and not checks


@pytest.mark.parametrize("provider", [bank_transfer.PROVIDER, yookassa.PROVIDER])
def test_success_binds_ciphertext_to_existing_order_and_exact_repo(renewal, provider):
    client, payments, grants, checks = renewal
    payment = payments.add(provider)
    response = _renew(client)
    assert response.status_code == 200, response.text
    assert response.json() == {"status": "paid"}
    assert checks == [("acme", "widget", GITHUB_TOKEN)]
    assert len(grants.attempts) == len(grants.saved) == 1
    payment_id, encrypted = grants.saved[0]
    assert payment_id == payment["id"]
    assert GITHUB_TOKEN not in encrypted
    assert GITHUB_TOKEN not in response.text
    assert open_paid_grant(
        encrypted, provider=provider, external_ref=REFERENCE,
        audit_id=AUDIT_ID, repo_full_name="acme/widget",
    ) == GITHUB_TOKEN
    with pytest.raises(DeliveryAuthorizationError):
        open_paid_grant(
            encrypted, provider=provider, external_ref="DRY-OTHER1",
            audit_id=AUDIT_ID, repo_full_name="acme/widget",
        )


@pytest.mark.parametrize("changes", [
    {"audit_id": "22222222-2222-4222-8222-222222222222"},
    {"status": "pending"}, {"status": "failed"}, {"product": "pro_tier"},
])
def test_unrelated_or_unsettled_receipt_cannot_renew(renewal, changes):
    client, payments, grants, checks = renewal
    payments.add(bank_transfer.PROVIDER, **changes)
    response = _renew(client)
    assert response.status_code == 404
    assert not grants.attempts and not checks


def test_forged_reference_cannot_reuse_an_existing_payment(renewal):
    client, payments, grants, checks = renewal
    payments.add(bank_transfer.PROVIDER)
    response = _renew(client, reference="DRY-FORGED")
    assert response.status_code == 404
    assert not grants.attempts and not checks


def test_ambiguous_reference_across_providers_is_not_guessed(renewal):
    client, payments, grants, checks = renewal
    payments.add(bank_transfer.PROVIDER)
    payments.add(yookassa.PROVIDER)
    response = _renew(client)
    assert response.status_code == 404
    assert not grants.attempts and not checks


@pytest.mark.parametrize("token", [None, "invalid token"])
def test_invalid_github_credential_never_mutates_grant(renewal, token):
    client, payments, grants, checks = renewal
    payments.add(bank_transfer.PROVIDER)
    response = _renew(client, github_token=token)
    assert response.status_code == 401
    assert not grants.attempts and not checks


@pytest.mark.parametrize("status,reason", [
    (403, "repository_write_access_required"),
    (502, "github_authorization_unavailable"),
])
def test_denied_or_unavailable_github_does_not_requeue(renewal, monkeypatch, status, reason):
    client, payments, grants, _ = renewal
    payments.add(bank_transfer.PROVIDER)

    def refuse(owner, repo, token):
        raise DeliveryAuthorizationError(status, reason)

    monkeypatch.setattr(paid_delivery_auth, "authorize_repository_delivery", refuse)
    response = _renew(client)
    assert response.status_code == status
    assert response.json()["detail"]["reason"] == reason
    assert not grants.attempts


def test_store_cas_refusal_never_reports_a_job_requeued(renewal):
    # The database tests prove these predicates. This boundary must respect
    # a failed CAS rather than report success after a terminal/racing job.
    client, payments, grants, _ = renewal
    payments.add(bank_transfer.PROVIDER)
    grants.allow_replace = False
    response = _renew(client)
    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "delivery_authorization_not_waiting"
    assert len(grants.attempts) == 1
    assert not grants.saved


def test_missing_encryption_configuration_does_not_mutate(renewal, monkeypatch):
    client, payments, grants, _ = renewal
    payments.add(bank_transfer.PROVIDER)
    monkeypatch.delenv("FIXPACK_DELIVERY_ENCRYPTION_KEY")
    response = _renew(client)
    assert response.status_code == 503
    assert not grants.attempts


@pytest.mark.parametrize("token", [None, "wrong", AUDIT_TOKEN])
def test_awaiting_status_exposes_order_only_after_audit_ownership(renewal, token):
    client, _, grants, _ = renewal

    class Jobs:
        async def get_by_audit(self, audit_id):
            return {"id": "fixture-job", "status": "awaiting_authorization", "pr_url": None}

    app.dependency_overrides[get_fixpack_repo] = lambda: Jobs()
    grants.funding = {"external_ref": REFERENCE, "encrypted_grant": "never-return-this"}
    response = client.get(
        f"/v1/audits/{AUDIT_ID}/fixpack-status", params={"token": token} if token else {},
    )
    if token == AUDIT_TOKEN:
        assert response.status_code == 200
        assert response.json()["delivery_reference"] == REFERENCE
        assert response.json()["status"] == "awaiting_authorization"
        assert grants.reads == ["fixture-job"]
    else:
        assert response.status_code == 404
        assert REFERENCE not in response.text
        assert not grants.reads
    assert "never-return-this" not in response.text
