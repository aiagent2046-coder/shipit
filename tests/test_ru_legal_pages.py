"""The Russian offer must quote the price the checkout actually charges.

IT DID NOT. The offer and the Russian storefront said «990 рублей» while
`BANK_TRANSFER_FIXPACK_PRICE_USD` said 10.00 and the audit page showed
$10.00 USD to the buyer. A public offer naming a price the checkout does not
charge is the first thing a payment aggregator sends back, and the first thing
a buyer would be right to complain about — and nothing in the repository
connected the two numbers, so neither could notice the other had moved.

These tests are that connection. They read the shipped TypeScript rather than
a copy of it, so a price changed on either side fails here until the other
follows.

WHY A PYTHON TEST OVER A .ts FILE. Because the authority is Python: the amount
the customer is charged comes from app/billing/bank_transfer.py. A TypeScript
test could only check the Russian pages against each other, which is the half
that was already consistent.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.billing.bank_transfer import _DEFAULT_FIXPACK_PRICE_USD

RU = Path(__file__).resolve().parent.parent / "web" / "src" / "app" / "ru"
PRICE_TS = RU / "price.ts"
PAGES = ("page.tsx", "offer/page.tsx", "refund/page.tsx", "privacy/page.tsx")


def read(name: str) -> str:
    return (RU / name).read_text(encoding="utf-8")


def rendered(name: str) -> str:
    """The page WITHOUT its import lines.

    Four mutants survived the first version of this file by deleting the
    place a constant is used and leaving the `import` that names it: a bare
    substring check saw the identifier and passed while the page had stopped
    showing anything. What matters is that the value reaches the reader, so
    the imports are stripped before looking.
    """
    return "\n".join(
        line for line in read(name).splitlines()
        if not line.lstrip().startswith("import")
    )


def _const(name: str) -> str:
    """One exported string constant out of price.ts."""
    match = re.search(rf'{name}\s*=\s*"([^"]*)"', PRICE_TS.read_text(encoding="utf-8"))
    assert match, f"{name} not found in {PRICE_TS}"
    return match.group(1)


# --- the price -------------------------------------------------------------

def test_the_offer_quotes_the_price_the_checkout_charges() -> None:
    assert _const("FIXPACK_PRICE_USD") == _DEFAULT_FIXPACK_PRICE_USD


def test_no_russian_page_still_names_a_rouble_price() -> None:
    """The literal that was wrong. A rouble figure anywhere in these pages
    means somebody quoted a price the product cannot charge — Robokassa
    converts at its own rate and the amount is not ours to state."""
    for name in PAGES:
        body = read(name)
        assert "990" not in body, name
        assert "₽" not in body, name
        assert "рублей за" not in body, name


def test_the_pages_take_the_price_from_one_place() -> None:
    """Both pages that name a price import it. A second literal is how the
    first divergence happened."""
    for name in ("page.tsx", "offer/page.tsx"):
        assert "{FIXPACK_PRICE_USD}" in rendered(name), name
        assert "./price" in read(name) or "../price" in read(name), name


def test_the_conversion_to_roubles_is_explained_where_the_price_is_named() -> None:
    """Quoting USD to a Russian buyer paying in roubles is only honest if the
    page says who converts and when."""
    for name in ("page.tsx", "offer/page.tsx"):
        assert "{CONVERSION_NOTE}" in rendered(name), name
    # The note itself has to say the three things that make the quote honest:
    # who converts, into what, and when the buyer sees the number.
    note = PRICE_TS.read_text(encoding="utf-8")
    body = note[note.index("CONVERSION_NOTE"):note.index("REFUND_DAYS")]
    assert "Robokassa" in body
    assert "рублях" in body
    assert "до подтверждения платежа" in body


# --- the refund -------------------------------------------------------------

def test_both_documents_state_the_same_refund_deadline() -> None:
    """A deadline in one document and not the other is a deadline a customer
    cannot rely on."""
    days = _const("REFUND_DAYS")
    assert days.strip()
    for name in ("offer/page.tsx", "refund/page.tsx"):
        assert "{REFUND_DAYS}" in rendered(name), name


def test_the_refund_terms_cover_a_paid_fix_pack_that_could_not_be_generated() -> None:
    """The case that actually happened. Audit bd970b2b was sold a Fix Pack and
    got "Nothing to auto-fix"; the infrastructure was fine, so the previous
    wording — which promised a refund only for "ошибка или недоступность
    инфраструктуры" — did not cover the one customer it needed to.

    Whether a machine broke is not what decides if somebody who received
    nothing gets their money back.
    """
    body = read("refund/page.tsx")
    assert "автоматическое исправление для данного аудита оказалось невозможным" in body
    assert "не предоставил Заказчику результат услуги" in body


def test_the_seller_details_agree_across_every_page() -> None:
    """An aggregator checks these against the registry, and one stale copy is
    a rejection. They are duplicated for legal reasons rather than technical
    ones, so the duplication gets a test instead of a refactor."""
    for field in ("672215400765", "326670000033868", "support@drydock.co"):
        present = [name for name in PAGES if field in read(name)]
        assert len(present) >= 3, (field, present)
