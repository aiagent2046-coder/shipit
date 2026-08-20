"""There is one way to pay, and this file is where that is written down.

Four providers were built: Telegram Stars, USDT/TRC20, PayPal and a manually
confirmed bank transfer. Three of them are gone. The remaining rail is the one
the Russian-language pages already name -- Robokassa, with the bank transfer
standing in until that shop connection is finished.

WHY A TEST AND NOT A DELETION NOTE. A removed provider comes back the way a
removed provider always comes back: someone needs "just a quick way to take a
card", finds the endpoint still routed or the module still importable, and
turns it on. Every assertion here is about ABSENCE, which is the one property
that cannot be checked by reading the diff that removed something.

The endpoints must 404 rather than 503. A 503 means "configure me"; a 404 means
"there is nothing here", and only the second is true. The distinction is not
pedantic: a provider left routed but unconfigured can be switched on by an
environment variable, which is exactly the state that lets money arrive on a
rail nobody is watching.

TELEGRAM IS THE EXCEPTION, AND NOT A HALF-MEASURE. The Stars rail is gone
exactly as far as the others: nothing can mint an invoice, and a pre-checkout
is declined. The BOT stays, because it is the operator's bank-transfer confirm
button and the only notification channel this product has. Its endpoint is
therefore still routed, and asserting a 404 on it would be asserting the wrong
thing -- tests/test_billing_telegram.py checks that nothing there sells.

WHAT IS DELIBERATELY NOT ASSERTED: that `payments` rows written by the removed
providers are unreadable. They must stay readable -- they are the books, and
several of them are refundable. tests/test_db_postgres_smoke.py checks that the
columns survive the removal of the code that wrote them.
"""

from __future__ import annotations

import importlib
import pathlib

import pytest
from fastapi.testclient import TestClient

from app.main import app

ROOT = pathlib.Path(__file__).resolve().parent.parent

client = TestClient(app, raise_server_exceptions=False)

# Every route the removed providers answered on, at the verb they answered on.
RETIRED_ENDPOINTS = [
    ("POST", "/v1/paypal/orders"),
    ("GET", "/v1/paypal/orders/ORDER-1"),
    ("POST", "/v1/paypal/subscriptions"),
    ("POST", "/v1/webhooks/paypal"),
    ("POST", "/v1/billing/usdt/invoice"),
    ("GET", "/v1/billing/usdt/invoice/INV-1"),
    ("POST", "/v1/audits/00000000-0000-0000-0000-000000000000/fixpack/usdt-invoice"),
    ("POST", "/internal/billing/poll-usdt"),
]

RETIRED_MODULES = [
    "app.billing.paypal",
    "app.routes.paypal",
    "app.billing.usdt_trc20",
]


@pytest.mark.parametrize("verb,path", RETIRED_ENDPOINTS,
                         ids=lambda v: v if v.startswith("/") else v.lower())
def test_a_retired_rail_answers_404_not_503(verb: str, path: str) -> None:
    resp = client.request(verb, path, json={})
    assert resp.status_code == 404, (
        f"{verb} {path} still answers {resp.status_code}. A retired payment "
        "rail must not be routed: 503 means 'configure me', and an env var is "
        "all that then stands between a stranger and a payment nobody watches."
    )


@pytest.mark.parametrize("name", RETIRED_MODULES)
def test_a_retired_provider_is_not_importable(name: str) -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(name)


def test_nothing_in_the_application_imports_a_retired_provider() -> None:
    """Belt and braces for the import check above: a module can be deleted
    from disk and still be named in a string, a lazy import, or a comment that
    reads like configuration. This greps the shipped tree."""
    offenders = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        text = path.read_text()
        for name in RETIRED_MODULES:
            if name in text:
                offenders.append(f"{path.relative_to(ROOT)}: {name}")
    assert not offenders, offenders


# --- the one rail that keeps its endpoint -----------------------------------

def test_the_telegram_webhook_is_still_routed() -> None:
    """The boundary for the paragraph above. The bot survives the removal of
    the Stars sale: it is where the operator taps Confirm on a bank transfer,
    and it is the only way this product can tell anyone anything.

    A 404 here would mean the operator cannot confirm a payment that has
    already arrived -- the opposite of what retiring a rail is for."""
    resp = client.post("/v1/webhooks/telegram", json={},
                       headers={"x-telegram-bot-api-secret-token": "s"})
    assert resp.status_code != 404
