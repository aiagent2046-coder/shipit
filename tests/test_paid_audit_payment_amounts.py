"""Check the report's rounding claim across the actual checkout/webhook path.

Provider HTTP and repository storage are fakes. The production row conversion,
price quoting, provider request and notification handler remain in use.
"""

from decimal import Decimal
import json

from fastapi import BackgroundTasks
import pytest

from app.db import _row_to_payment
from app.main import app
from app.routes.yookassa import receive_notification
from tests.test_billing_bank_transfer import FakeFixpackRepo, FakePaymentRepo
from tests.test_routes_yookassa import (
    PAYER, PAYMENT_ID, _audit_with_findings, _created, _request, _succeeded,
    _wire, client,
)


@pytest.fixture(autouse=True)
def isolated_shop(monkeypatch):
    monkeypatch.setenv("YOOKASSA_SHOP_ID", "test-shop")
    monkeypatch.setenv("YOOKASSA_SECRET_KEY", "test_secret")
    monkeypatch.delenv("YOOKASSA_VAT_CODE", raising=False)
    yield
    app.dependency_overrides.clear()


@pytest.mark.anyio
@pytest.mark.parametrize("configured_price", [
    "0.01", "0.29", "2.67", "990.00", "990.07", "999.99", "1000000.99", "2.675",
])
async def test_quoted_card_amount_is_accepted_after_numeric_row_conversion(
    monkeypatch, configured_price,
):
    monkeypatch.setenv("BANK_TRANSFER_FIXPACK_PRICE_RUB", configured_price)
    payments, jobs = FakePaymentRepo(), FakeFixpackRepo()
    audits, audit_id = _audit_with_findings()
    sent = []
    _wire(payments, audits, jobs, transport=_created(sent))

    response = client.post(f"/v1/audits/{audit_id}/fixpack/yookassa", json=PAYER)
    assert response.status_code == 201
    checkout = response.json()
    provider_amount = json.loads(sent[0].content)["amount"]["value"]
    assert provider_amount == checkout["amount"]

    row = await payments.get_by_external_ref("yookassa", checkout["reference"])
    # Exercise the application's conversion of a PostgreSQL numeric value.
    # This checks no live database or payment service.
    row.update(_row_to_payment({**row, "amount": Decimal(provider_amount)}))
    assert isinstance(row["amount"], float)

    background = BackgroundTasks()
    result = await receive_notification(
        _request({"event": "payment.succeeded", "object": {"id": PAYMENT_ID}}),
        background, payment_repo=payments, fixpack_repo=jobs, audit_repo=audits,
        transport=_succeeded(value=provider_amount, reference=checkout["reference"]),
    )
    assert result == {"ok": True}
    assert row["status"] == "completed"
    assert len(jobs.rows) == 1
    assert len(background.tasks) == 1  # Do not send the deferred notification.
