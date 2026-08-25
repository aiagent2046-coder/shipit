/**
 * The Fix Pack price, as the Russian-language pages must state it.
 *
 * WHY THIS FILE EXISTS. The offer and the storefront page once said «990
 * рублей» while the product charged whatever `BANK_TRANSFER_FIXPACK_PRICE_USD`
 * said — $10.00 — and showed that on the audit page in USD. A public offer
 * quoting a price the checkout does not charge is the first thing a payment
 * aggregator rejects, and the first thing a buyer would be right to complain
 * about.
 *
 * So the number lives once, and tests/test_ru_legal_pages.py pins it against
 * `_DEFAULT_FIXPACK_PRICE_RUB` in app/billing/bank_transfer.py. Change the
 * price there and that test fails until this follows.
 *
 * IT IS ROUBLES NOW, AND THAT IS THE POINT. The pages used to quote dollars
 * and then explain, in CONVERSION_NOTE, that the rouble sum would be whatever
 * the payment system's rate made it at the moment of payment. ЮMoney rejected
 * the site for it on 2026-08-23 under the heading "укажите фиксированные
 * цены", and they were right on the substance even though their template names
 * a phrase («от 100 ₽») the site never used: a buyer who cannot learn the
 * rouble figure until the payment page has not been quoted a price.
 *
 * CONVERSION_NOTE is gone rather than translated. There is nothing left to
 * convert — the price is quoted, charged and settled in one currency — and a
 * sentence explaining an exchange rate that no longer happens would be the
 * same defect written more carefully.
 *
 * It is deliberately NOT fetched at render time. These are legal documents:
 * they have to render identically whether or not the API answers, and a price
 * that can vanish into a loading state is worse than one a test keeps honest.
 */

/** Digits only. The «₽» is written next to it in the pages, so that the number
 *  can be pinned against the backend's without the test having to know how
 *  each page decorates it. */
export const FIXPACK_PRICE_RUB = "990";

/** How long we take to decide on a refund and send it to the payment system.
 *  Stated in both the offer and the refund terms, from here, for the same
 *  reason the price is. */
export const REFUND_DAYS = "5 рабочих дней";

/** The payment aggregator named in the offer, the refund terms and the privacy
 *  policy — the answer to "who is holding my money and where do I complain".
 *
 *  Kept here rather than typed into four documents because it has already
 *  changed twice, and the second time for a subtler reason than the first.
 *
 *  The pages named Robokassa while an application to ЮMoney was under review,
 *  so a ЮMoney reviewer opening the offer read that a competitor processed the
 *  payments. Then they named ЮMoney while the connected shop was ЮKassa —
 *  related brands, and not interchangeable in a document that answers "who is
 *  holding my money and where do I complain". ЮKassa is the acquiring service
 *  the payment actually goes through; that is the name on the payment page a
 *  buyer sees and the one that can act on a complaint.
 *
 *  One constant means the next switch is one edit and a test, not a search. */
export const PAYMENT_PROVIDER = "ЮKassa";
