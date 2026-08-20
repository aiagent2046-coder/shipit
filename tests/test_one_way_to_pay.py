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
]

RETIRED_MODULES = [
    "app.billing.paypal",
    "app.routes.paypal",
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
