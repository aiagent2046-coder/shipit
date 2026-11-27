"""Both payment rails reject unproven repository authority before an invoice.

Network authorization is the only stub: checkout, grant sealing and payment
binding run together. No actual GitHub or payment credentials are used.
"""
from __future__ import annotations

import json

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.main import (
    app,
    get_audit_repo,
    get_billing_transport,
    get_fixpack_repo,
    get_payment_repo,
)
from app.services.deploypack import paid_delivery_auth
from app.services.deploypack.delivery_auth import DeliveryAuthorizationError
from tests.test_billing_bank_transfer import (
    BANK_ENV,
    PAYER,
    FakeAuditRepo,
    FakeFixpackRepo,
    FakePaymentRepo,
)

CALLER_TOKEN = "github-pat-checkout-fixture"


@pytest.fixture
def checkout_context(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("FIXPACK_DELIVERY_ENCRYPTION_KEY", key.decode())
    monkeypatch.setenv("YOOKASSA_SHOP_ID", "test-shop")
    monkeypatch.setenv("YOOKASSA_SECRET_KEY", "fixture-payment-secret")
    monkeypatch.setenv("GITHUB_PR_TOKEN", "operator-token-must-not-authorize")
    for name, value in BANK_ENV.items():
        monkeypatch.setenv(name, value)
    payments, audits, jobs = FakePaymentRepo(), FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add()
    provider_requests = []
    authorization_requests = []

    def github_authorize(owner, repo, token):
        authorization_requests.append((owner, repo, token))

    def payment_provider(request):
        # A notification can race this response; the authority must already
        # be durably associated with the order before the charge is opened.
        assert len(payments.rows) == len(payments.delivery_grants) == 1
        provider_requests.append(request)
        return httpx.Response(200, json={
            "id": "fixture-provider-payment", "status": "pending",
            "confirmation": {
                "type": "redirect", "confirmation_url": "https://example.invalid/pay",
            },
        })

    monkeypatch.setattr(paid_delivery_auth, "authorize_repository_delivery", github_authorize)
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_audit_repo] = lambda: audits
    app.dependency_overrides[get_fixpack_repo] = lambda: jobs
    app.dependency_overrides[get_billing_transport] = lambda: httpx.MockTransport(payment_provider)
    with TestClient(app) as client:
        yield client, audit, payments, provider_requests, authorization_requests, key
    for dependency in (get_payment_repo, get_audit_repo, get_fixpack_repo, get_billing_transport):
        app.dependency_overrides.pop(dependency, None)


@pytest.mark.parametrize("rail", ["bank-transfer", "yookassa"])
@pytest.mark.parametrize("token,reason", [
    (None, "github_token_required"), ("invalid token", "invalid_github_token"),
])
def test_missing_or_invalid_caller_token_never_opens_order(rail, token, reason, checkout_context):
    client, audit, payments, provider_requests, authorization_requests, _ = checkout_context
    response = client.post(
        f"/v1/audits/{audit['id']}/fixpack/{rail}", json=PAYER,
        headers={"X-GitHub-Token": token} if token else {},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["reason"] == reason
    assert not payments.rows
    assert not payments.delivery_grants
    assert not provider_requests
    assert not authorization_requests


@pytest.mark.parametrize("rail", ["bank-transfer", "yookassa"])
@pytest.mark.parametrize("status,reason", [
    (403, "repository_write_access_required"),
    (502, "github_authorization_unavailable"),
])
def test_denied_or_unavailable_github_cannot_charge(
    rail, status, reason, checkout_context, monkeypatch,
):
    client, audit, payments, provider_requests, _, _ = checkout_context

    def refuse(owner, repo, token):
        assert (owner, repo, token) == ("acme", "widget", CALLER_TOKEN)
        raise DeliveryAuthorizationError(status, reason)

    monkeypatch.setattr(paid_delivery_auth, "authorize_repository_delivery", refuse)
    response = client.post(
        f"/v1/audits/{audit['id']}/fixpack/{rail}", json=PAYER,
        headers={"X-GitHub-Token": CALLER_TOKEN},
    )
    assert response.status_code == status
    assert response.json()["detail"]["reason"] == reason
    assert not payments.rows
    assert not payments.delivery_grants
    assert not provider_requests
    assert CALLER_TOKEN not in response.text


@pytest.mark.parametrize("rail", ["bank-transfer", "yookassa"])
def test_unconfigured_encryption_never_opens_order(rail, checkout_context, monkeypatch):
    client, audit, payments, provider_requests, _, _ = checkout_context
    monkeypatch.delenv("FIXPACK_DELIVERY_ENCRYPTION_KEY")
    response = client.post(
        f"/v1/audits/{audit['id']}/fixpack/{rail}", json=PAYER,
        headers={"X-GitHub-Token": CALLER_TOKEN},
    )
    assert response.status_code == 503
    assert not payments.rows
    assert not payments.delivery_grants
    assert not provider_requests


@pytest.mark.parametrize("rail", ["bank-transfer", "yookassa"])
def test_order_persists_only_encrypted_exact_repository_grant(rail, checkout_context):
    client, audit, payments, provider_requests, authorization_requests, key = checkout_context
    response = client.post(
        f"/v1/audits/{audit['id']}/fixpack/{rail}", json=PAYER,
        headers={"X-GitHub-Token": CALLER_TOKEN},
    )
    assert response.status_code == 201, response.text
    assert authorization_requests == [("acme", "widget", CALLER_TOKEN)]
    assert len(payments.rows) == len(payments.delivery_grants) == 1
    payment = next(iter(payments.rows.values()))
    encrypted = payments.delivery_grants[payment["id"]]
    assert CALLER_TOKEN not in encrypted
    assert CALLER_TOKEN not in repr(payment)
    assert CALLER_TOKEN not in response.text
    decoded = Fernet(key).decrypt(encrypted.encode()).decode()
    # Binding travels inside authenticated ciphertext, not mutable fields
    # returned to the buyer or copied into provider metadata.
    assert CALLER_TOKEN in decoded
    assert audit["id"] in decoded
    assert payment["external_ref"] in decoded
    assert payment["provider"] in decoded
    assert "acme/widget" in decoded
    for request in provider_requests:
        assert CALLER_TOKEN not in request.content.decode()
        assert CALLER_TOKEN not in str(request.headers)
        assert json.loads(request.content)["metadata"] == {
            "reference": payment["external_ref"],
        }


@pytest.mark.parametrize("rail", ["bank-transfer", "yookassa"])
def test_repository_name_from_request_cannot_override_audit(rail, checkout_context):
    client, audit, _, _, authorization_requests, _ = checkout_context
    response = client.post(
        f"/v1/audits/{audit['id']}/fixpack/{rail}?repo=outsider/project",
        json={**PAYER, "repo_url": "https://github.com/outsider/project"},
        headers={"X-GitHub-Token": CALLER_TOKEN},
    )
    assert response.status_code == 201, response.text
    assert authorization_requests == [("acme", "widget", CALLER_TOKEN)]


@pytest.mark.parametrize("rail", ["bank-transfer", "yookassa"])
def test_failed_grant_persistence_does_not_open_payment(rail, checkout_context, monkeypatch):
    client, audit, payments, provider_requests, _, _ = checkout_context

    async def unavailable(**kwargs):
        assert kwargs.get("delivery_grant")
        assert CALLER_TOKEN not in kwargs["delivery_grant"]
        return None

    monkeypatch.setattr(payments, "create", unavailable)
    response = client.post(
        f"/v1/audits/{audit['id']}/fixpack/{rail}", json=PAYER,
        headers={"X-GitHub-Token": CALLER_TOKEN},
    )
    assert response.status_code == 503
    assert not payments.rows
    assert not provider_requests
