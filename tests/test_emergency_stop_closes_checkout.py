"""The emergency stop must close the checkout, not only the work.

Before this, `llm_paid_ops` paused audit intake and the Fix Pack worker while
leaving both invoice creators open. Engaging the stop mid-incident would have
kept taking money for work that could not run -- the worst possible ordering.

These tests pin the direction: with the flag off, no new invoice can be opened
on either bank-transfer route, and the payer sees the operator's note rather
than a card number.
"""
from fastapi.testclient import TestClient

from app.main import (
    app,
    _reset_service_flag_cache,
    get_audit_repo,
    get_payment_repo,
    get_service_flags_repo,
)
from tests.test_llm_enforcement import FakeServiceFlagsRepo

client = TestClient(app)

_PAYER = {"payer_name": "Test Buyer", "payer_email": "buyer@example.com"}


class _AuditRepoWithRepoUrl:
    """Enough audit for the Fix Pack route to get past its own 404/422 gates,
    so a 503 here can only have come from the emergency stop."""

    async def get(self, audit_id):
        return {
            "id": audit_id,
            "repo_url": "https://github.com/example/app",
            "status": "completed",
        }


class _ExplodingPaymentRepo:
    """Any call means the stop failed to block the request before persistence."""

    def __getattr__(self, name):
        raise AssertionError(
            f"payment repo touched ({name}) while the emergency stop was engaged"
        )


def _paused(note="paused by alice"):
    _reset_service_flag_cache()
    app.dependency_overrides[get_service_flags_repo] = \
        lambda: FakeServiceFlagsRepo(enabled=False, note=note)
    app.dependency_overrides[get_payment_repo] = lambda: _ExplodingPaymentRepo()
    app.dependency_overrides[get_audit_repo] = lambda: _AuditRepoWithRepoUrl()


def _clear():
    app.dependency_overrides.clear()
    _reset_service_flag_cache()


def test_emergency_stop_blocks_fixpack_invoice():
    _paused()
    try:
        resp = client.post(
            "/v1/audits/11111111-1111-4111-8111-111111111111"
            "/fixpack/bank-transfer",
            json=_PAYER,
        )
    finally:
        _clear()

    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert detail["reason"] == "service_paused"
    assert detail["detail"] == "paused by alice"


def test_emergency_stop_blocks_pro_invoice():
    _paused()
    try:
        resp = client.post("/v1/billing/bank-transfer/pro", json=_PAYER)
    finally:
        _clear()

    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "service_paused"


def test_stop_checked_before_rate_limit_is_consumed():
    """A paused service must not burn the caller's invoice quota: fire more
    requests than the limiter allows and every one must still be refused for
    being paused, never rate-limited.

    Asserting on the reason, not the status code. An earlier version of this
    test checked `status_code == 503` and passed against unfixed code, because
    an unconfigured test deployment returns 503 for a different reason
    entirely -- "bank transfer isn't configured". The status code alone cannot
    tell the two apart, so it proved nothing.
    """
    _paused()
    try:
        reasons = {
            client.post(
                "/v1/billing/bank-transfer/pro", json=_PAYER
            ).json()["detail"]["reason"]
            for _ in range(12)
        }
    finally:
        _clear()

    assert reasons == {"service_paused"}, (
        f"expected every request to be refused as paused, saw {reasons}"
    )
