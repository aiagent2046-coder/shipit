"""Public storefront endpoints: what is on sale and how to pay for it.

Both handlers are unauthenticated and read their values from the same
accessors the invoice creators use, so an advertised figure cannot drift from
a charged one.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.billing import bank_transfer

router = APIRouter()


@router.get("/v1/pricing")
async def get_pricing() -> dict:
    """What is on sale and what it costs, for the storefront.

    Read from the same accessor the invoice creator calls
    (bank_transfer.fixpack_price_rub) so the advertised figure cannot drift
    from the charged one. That is the whole reason this exists as an endpoint
    instead of a number typed into the page: /pricing previously showed no
    price at all, and the comparison table it did show had been stale since
    the free tier dropped to 3 audits.

    FIX PACK ONLY, by product decision. The free tier is static-only and
    costs us nothing to run, so Pro's single live benefit -- a higher daily
    audit limit -- is not something we are willing to take money for. The Pro
    purchase routes stay reachable for the existing customer and the bot;
    they are simply no longer advertised.

    USD only, which is now the whole story: the two channels that carried
    their own prices in their own units -- Stars in XTR, USDT in micro-dollars
    -- are gone. One rail, one currency, one accessor.

    ROUBLES SINCE 2026-08-23. This used to return USD beside a page that
    explained the buyer would be charged some rouble figure at the payment
    system's rate. ЮMoney rejected the site for it, and rightly: a price the
    buyer cannot know before the payment page is not a price. The aggregator
    settles in roubles, so the product is quoted in roubles, and there is
    nothing left to convert. When one is finally connected its figure must
    come from this accessor and not from a second one beside it.

    Deliberately separate from /v1/billing/details: that payload carries a
    card number for the footer, and a page that only needs a price should not
    have to fetch a payment instrument to get one.
    """
    return {
        "fixpack": {
            "amount": bank_transfer.fixpack_price_rub(),
            "currency": bank_transfer.CURRENCY,
        },
    }


@router.get("/v1/billing/details")
async def get_billing_details() -> dict:
    """The publishable payment requisites, for the site footer.

    Public and unauthenticated on purpose: the footer renders on every page,
    including to visitors who have not started a purchase, and the operator's
    decision is that these requisites are published information. This endpoint
    is the single source for them -- they are still never mirrored into a
    NEXT_PUBLIC_* build variable, so rotating the card is an env change and a
    restart, with no frontend rebuild.

    Returns 200 with `bank: null` rather than 503 when bank transfer isn't
    configured. A footer is not a checkout: an unconfigured deployment should
    render a footer without a requisites block, not an error.
    """
    return {"bank": bank_transfer.bank_details_from_env()}
