"""The Russian offer must quote the price the checkout actually charges.

IT DID NOT, TWICE, IN OPPOSITE DIRECTIONS.

First the offer and the Russian storefront said «990 рублей» while
`BANK_TRANSFER_FIXPACK_PRICE_USD` said 10.00 and the audit page showed
$10.00 USD to the buyer. A public offer naming a price the checkout does not
charge is the first thing a payment aggregator sends back, and the first thing
a buyer would be right to complain about — and nothing in the repository
connected the two numbers, so neither could notice the other had moved.

The fix at the time was to quote dollars everywhere and explain the conversion.
ЮMoney rejected the site for that on 2026-08-23: a buyer who cannot learn the
rouble figure until the payment page has not been quoted a price at all, which
is the substance behind their "укажите фиксированные цены" template. So the
product now charges roubles, the pages quote roubles, and the assertion that
no rouble figure may appear — correct while the checkout could not charge one —
is inverted below into a requirement that one must.

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

from app.billing.bank_transfer import CURRENCY, _DEFAULT_FIXPACK_PRICE_RUB

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
    """The pages carry digits only; the backend carries a 2dp amount. Compared
    as numbers so the pages are not forced to print «990.00 ₽» at a reader who
    would only wonder what the kopecks are for."""
    assert float(_const("FIXPACK_PRICE_RUB")) == float(_DEFAULT_FIXPACK_PRICE_RUB)


def test_the_product_actually_charges_roubles() -> None:
    """The pages may only quote roubles because the checkout charges them.
    Quoting a currency the provider does not use is how this went wrong the
    first time, in the other direction."""
    assert CURRENCY == "RUB"


def test_every_page_that_names_a_price_names_a_fixed_rouble_one() -> None:
    """WHAT ЮMONEY ASKED FOR, and the inverse of what this file asserted
    before. Their wording is a template — the site never said «от 100 ₽» — but
    the substance was right: a dollar figure plus "the rouble amount is
    whatever the rate makes it" is not a price a buyer can know in advance."""
    for name in ("page.tsx", "offer/page.tsx"):
        body = rendered(name)
        assert "{FIXPACK_PRICE_RUB} ₽" in body, name
        assert "USD" not in body, name
        assert "$" not in body, name


def test_no_page_hedges_the_price(  ) -> None:
    """The hedge, in any of the shapes it comes in. Each of these turns a
    stated price back into an estimate, which is the thing that was rejected."""
    for name in PAGES:
        body = read(name)
        for hedge in ("от 9", "от 1", "примерно", "около", "по курсу",
                      "курсу на момент"):
            assert hedge not in body, f"{name} hedges the price: {hedge!r}"


def test_the_pages_take_the_price_from_one_place() -> None:
    """Both pages that name a price import it. A second literal is how the
    first divergence happened."""
    for name in ("page.tsx", "offer/page.tsx"):
        assert "{FIXPACK_PRICE_RUB}" in rendered(name), name
        assert "./price" in read(name) or "../price" in read(name), name


def test_no_page_still_names_the_previous_payment_provider() -> None:
    """A ЮMoney reviewer opening the offer read that Robokassa processed the
    payments, because the pages named the aggregator whose application was
    under review LAST time. One constant now, so the next switch is one edit."""
    for name in PAGES:
        assert "Robokassa" not in read(name), name
    assert _const("PAYMENT_PROVIDER")


def test_the_provider_is_named_where_money_and_data_change_hands() -> None:
    """The offer says who takes the payment, the refund terms say who sends it
    back, and the privacy policy says who receives the card details. All three
    are answers to "who is holding my money" and none may be left blank."""
    for name in ("offer/page.tsx", "refund/page.tsx", "privacy/page.tsx"):
        assert "{PAYMENT_PROVIDER}" in rendered(name), name


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


SELLER_ADDRESS = "214030, г. Смоленск, ул. Некрасова, д. 16"

FOOTER = (
    Path(__file__).resolve().parent.parent
    / "web" / "src" / "components" / "Footer.tsx"
)


def test_the_seller_details_agree_across_every_page() -> None:
    """An aggregator checks these against the registry, and one stale copy is
    a rejection. They are duplicated for legal reasons rather than technical
    ones, so the duplication gets a test instead of a refactor.

    THE ADDRESS IS ON THIS LIST NOW, and it is the field that went wrong. The
    pages said «Смоленская область, Угранский район, село Угра» while the ИП's
    bank details said «214030 г. Смоленск» — same street and house number,
    different town. The other three fields were pinned here and stayed right;
    the address was not and did not. A reviewer comparing the offer against the
    bank requisites is looking at exactly this."""
    for field in ("672215400765", "326670000033868", "support@drydock.co",
                  SELLER_ADDRESS):
        present = [name for name in PAGES if field in read(name)]
        assert len(present) >= 3, (field, present)


def test_the_footer_carries_the_same_address_as_the_documents() -> None:
    """The footer renders on every page including the English ones, so it is
    the copy an aggregator meets first and the one most easily forgotten. It
    was: the address was updated in four documents and the footer read on."""
    footer = FOOTER.read_text(encoding="utf-8")
    assert SELLER_ADDRESS in footer
    assert "672215400765" in footer


def test_no_page_still_carries_the_previous_address() -> None:
    """Stated separately from the agreement check above, because agreement is
    satisfied by every copy being wrong together — which is how a stale address
    survives a rename."""
    for path in [RU / name for name in PAGES] + [FOOTER]:
        assert "Угра" not in path.read_text(encoding="utf-8"), path.name
