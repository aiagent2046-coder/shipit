"""The words a customer reads about their own money, in their own language.

THE FAILURE THIS GUARDS AGAINST IS DRIFT, not a wrong string. Somebody improves
the English refund notice, the Russian one keeps the old wording, and nothing
fails — the customer just gets a worse message in one language than the other,
and only they find out. So most of what is checked below is that the two
languages stay the same SHAPE: same placeholders filled, same facts present,
same things absent.

The one fact that must be absent is the operator's refund reason. It is a note
for the books, written to be true rather than to be read by the person it is
about, and quoting it back is at best clumsy and at worst an accusation. That
has to hold in every language, which is exactly the kind of property a second
translation quietly breaks.
"""

from __future__ import annotations

import pytest

from app.notify import messages
from app.notify.messages import EN, RU, SUPPORTED


# --- what language to write in ---------------------------------------------

@pytest.mark.parametrize("given,expected", [
    ("ru", RU), ("RU", RU), ("ru-RU", RU), ("ru_RU", RU), ("  ru-ru  ", RU),
    ("en", EN), ("en-GB", EN), ("EN-us", EN),
])
def test_a_browser_locale_is_reduced_to_a_language(given, expected) -> None:
    """The checkout sends whatever `navigator.language` gave it, and that is
    `ru-RU` or `en-GB` at least as often as a bare `ru`."""
    assert messages.normalize(given) == expected


@pytest.mark.parametrize("given", [None, "", "   ", "de", "fr-FR", "zz", "🙂"])
def test_anything_we_cannot_write_becomes_english(given) -> None:
    """Unknown is not a reason to withhold the message, and not a reason to
    guess. Every payment made before migration 0033 arrives here as None."""
    assert messages.normalize(given) == EN


def test_null_does_not_become_russian_because_the_operator_is_russian() -> None:
    """Stated as its own test because it is the tempting mistake. Every
    historical payment has no locale; defaulting those to Russian would write
    to English-speaking customers in a language they never asked for."""
    assert messages.normalize(None) == EN


# --- both languages say the same things ------------------------------------

@pytest.mark.parametrize("locale", SUPPORTED)
@pytest.mark.parametrize("product", ["fixpack", "pro_tier"])
def test_a_confirmation_carries_the_reference_in_every_language(
    locale, product,
) -> None:
    """The reference is what the payer quotes back to support. A translation
    that drops it leaves them with a friendly message and no way to be
    helped."""
    body = messages.confirmation_body(
        product=product, reference="DRY-ABC123",
        site_url="https://drydock.co", locale=locale,
    )
    assert "DRY-ABC123" in body
    # And no unfilled placeholder survived into what the customer reads.
    assert "{" not in body and "}" not in body


@pytest.mark.parametrize("locale", SUPPORTED)
def test_a_fix_pack_confirmation_says_a_pull_request_is_coming(locale) -> None:
    """The two products need different sentences: one opens a pull request,
    the other hands over a key. Getting that wrong in one language only is
    exactly what drift looks like."""
    body = messages.confirmation_body(
        product="fixpack", reference="DRY-1", site_url="https://drydock.co",
        locale=locale,
    )
    assert ("pull request" in body) or ("пул-реквест" in body)
    assert "/link" not in body


@pytest.mark.parametrize("locale", SUPPORTED)
def test_a_pro_confirmation_points_at_where_the_key_is(locale) -> None:
    body = messages.confirmation_body(
        product="pro_tier", reference="DRY-1", site_url="https://drydock.co",
        locale=locale,
    )
    assert "https://drydock.co/link" in body


@pytest.mark.parametrize("locale", SUPPORTED)
def test_an_unknown_product_still_produces_a_message(locale) -> None:
    """`product` is free text in the database (migration 0007 says so on
    purpose). A value this module has no sentence for must not raise on a path
    where the money has already moved."""
    body = messages.confirmation_body(
        product="something-new", reference="DRY-1",
        site_url="https://drydock.co", locale=locale,
    )
    assert body and "DRY-1" in body
    assert messages.confirmation_subject(product="something-new", locale=locale)


@pytest.mark.parametrize("locale", SUPPORTED)
def test_a_refund_names_the_amount_and_the_order(locale) -> None:
    body = messages.refund_body(
        amount=10.79, currency="USD", reference="DRY-REFUND", locale=locale,
    )
    assert "10.79 USD" in body
    assert "DRY-REFUND" in body
    assert "{" not in body and "}" not in body


@pytest.mark.parametrize("locale", SUPPORTED)
def test_a_refund_with_no_amount_does_not_invent_one(locale) -> None:
    """"0.00" would be a number this text asserts, read by somebody counting
    their money. Naming none is honest; naming the wrong one is not."""
    body = messages.refund_body(
        amount=None, currency=None, reference="DRY-1", locale=locale,
    )
    assert "0.00" not in body
    assert body.strip()


@pytest.mark.parametrize("locale", SUPPORTED)
def test_a_refund_with_no_reference_leaves_no_dangling_label(locale) -> None:
    """A "Order reference:" with nothing after it reads as a bug in the
    message, which is not what somebody chasing their money needs to see."""
    body = messages.refund_body(
        amount=10.79, currency="USD", reference="", locale=locale,
    )
    assert "reference:" not in body.lower()
    assert "номер заказа" not in body.lower()


# --- what must be absent, in every language ---------------------------------

@pytest.mark.parametrize("locale", SUPPORTED)
def test_the_operators_reason_is_nowhere_in_the_refund_text(locale) -> None:
    """refund_body is not even GIVEN the reason, and this asserts the shape
    that keeps it that way: nothing in the signature can carry it in."""
    import inspect

    params = set(inspect.signature(messages.refund_body).parameters)
    assert "reason" not in params
    assert params == {"amount", "currency", "reference", "locale"}


# --- adding a language is a deliberate act ----------------------------------

def test_every_supported_language_has_every_message() -> None:
    """SUPPORTED is written by hand rather than derived from the dictionaries,
    so that adding a language means writing all of its text. Without this, a
    half-translated language would silently fall back for the strings somebody
    forgot — the drift this module exists to prevent, arriving through the
    front door."""
    for locale in SUPPORTED:
        assert messages.refund_subject(locale=locale)
        assert messages.refund_body(
            amount=1.0, currency="USD", reference="R", locale=locale)
        for product in ("fixpack", "pro_tier"):
            assert messages.confirmation_subject(
                product=product, locale=locale)
            assert messages.confirmation_body(
                product=product, reference="R",
                site_url="https://drydock.co", locale=locale)


def test_the_two_languages_are_actually_different() -> None:
    """The boundary. A copy-paste that left Russian as English would pass
    every test above, because every one of them asks whether the FACTS are
    present rather than which words carry them."""
    en = messages.refund_body(
        amount=10.79, currency="USD", reference="R", locale=EN)
    ru = messages.refund_body(
        amount=10.79, currency="USD", reference="R", locale=RU)
    assert en != ru
    assert any("Ѐ" <= c <= "ӿ" for c in ru), "no Cyrillic in the Russian"
    assert not any("Ѐ" <= c <= "ӿ" for c in en), "Cyrillic in the English"
