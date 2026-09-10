"""Funding classification with synthetic records; no providers or LLM calls."""
from unittest.mock import AsyncMock

import pytest

from app.billing import grant_fixpack
from app.fixpack_funding import funding_key
from app.notify.messages import funding_review_message


@pytest.mark.parametrize("inserted", [True, False])
async def test_own_payment_is_not_a_second_payment(inserted):
    key = funding_key("bank_transfer", "test-charge")
    jobs = AsyncMock()
    jobs.create_paid.return_value = {"id": "job-1", "funding_key": key, "inserted": inserted}
    payments = AsyncMock()
    payments.get_by_external_ref.return_value = None
    result = await grant_fixpack(
        fixpack_repo=jobs, payment_repo=payments, audit_repo=None,
        provider="bank_transfer", external_ref="test-charge", amount=990,
        currency="RUB", audit_id=None, invoice_payment_id="invoice-1",
    )
    assert result["funding_review_required"] is False
    jobs.create_paid.assert_awaited_once_with(audit_id=None, stack="unknown", funding_key=key)
    assert payments.mark_completed_fixpack.await_args.kwargs["fixpack_job_id"] == "job-1"


@pytest.mark.parametrize("stored_key", [None, funding_key("bank_transfer", "other-charge")])
@pytest.mark.parametrize("completed", [False, True])
async def test_another_payment_or_unknown_funding_requires_review_on_every_retry(stored_key, completed):
    jobs = AsyncMock()
    jobs.create_paid.return_value = jobs.get.return_value = {
        "id": "job-1", "funding_key": stored_key, "inserted": False,
    }
    payments = AsyncMock()
    payments.get_by_external_ref.return_value = (
        {"id": "invoice-2", "status": "completed", "fixpack_job_id": "job-1"} if completed else None
    )
    result = await grant_fixpack(
        fixpack_repo=jobs, payment_repo=payments, audit_repo=None,
        provider="bank_transfer", external_ref="test-charge", amount=990,
        currency="RUB", audit_id=None, invoice_payment_id="invoice-2",
    )
    assert result["funding_review_required"] is True
    if completed:
        jobs.create_paid.assert_not_awaited()
        payments.mark_completed_fixpack.assert_not_awaited()
    else:
        payments.mark_completed_fixpack.assert_awaited_once()


async def test_refused_payment_completion_does_not_report_grant_success():
    payments, jobs = AsyncMock(), AsyncMock()
    payments.get_by_external_ref.return_value = None
    payments.mark_completed_fixpack.return_value = None
    jobs.create_paid.return_value = {"id": "job-1", "funding_key": funding_key("bank", "charge")}
    result = await grant_fixpack(
        fixpack_repo=jobs, payment_repo=payments, audit_repo=None,
        provider="bank", external_ref="charge", amount=990, currency="RUB",
        audit_id=None, invoice_payment_id="invoice-1",
    )
    assert result is None


def test_funding_identity_separates_providers_and_delimiters():
    assert funding_key("a:b", "c") != funding_key("a", "b:c")
    assert funding_key("bank_transfer", "charge") != funding_key("yookassa", "charge")


def test_review_message_never_claims_a_job_or_refund_was_issued():
    _, text = funding_review_message(reference="TEST-REF", locale="en")
    assert "has not been confirmed" in text and "No refund has been issued" in text
    assert "TEST-REF" in text
    _, russian = funding_review_message(reference="TEST-REF", locale="ru")
    assert "Возврат ещё не выполнен" in russian


async def test_customer_notification_does_not_promise_work_for_second_payment():
    from app.billing.bank_transfer import _tell_the_payer

    notify = AsyncMock()
    await _tell_the_payer(
        {"external_ref": "TEST-SECOND", "payer_email": "payer@example.invalid"},
        product="fixpack", notify=notify, funding_review_required=True,
    )
    notify.assert_awaited_once()
    text = notify.await_args.kwargs["body"]
    assert "has not been confirmed" in text and "No refund has been issued" in text
    assert "TEST-SECOND" in text
    assert "queued" not in text
