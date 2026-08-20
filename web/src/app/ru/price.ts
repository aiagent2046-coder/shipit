/**
 * The Fix Pack price, as the Russian-language legal pages must state it.
 *
 * WHY THIS FILE EXISTS. The offer and the storefront page used to say
 * «990 рублей» while the product charged whatever
 * `BANK_TRANSFER_FIXPACK_PRICE_USD` said — $10.00 — and showed that on the
 * audit page in USD. A public offer quoting a price the checkout does not
 * charge is the first thing a payment aggregator rejects, and the first thing
 * a buyer would be right to complain about.
 *
 * So the number lives once, and tests/test_ru_legal_pages.py pins it against
 * `_DEFAULT_FIXPACK_PRICE_USD` in app/billing/bank_transfer.py. Change the
 * price there and that test fails until this follows.
 *
 * It is deliberately NOT fetched at render time. These are legal documents:
 * they have to render identically whether or not the API answers, and a
 * price that can vanish into a loading state is worse than one a test keeps
 * honest.
 */
export const FIXPACK_PRICE_USD = "10.00";

/** Robokassa settles in roubles; we quote in USD. Said the same way on every
 *  page that names the price, so the buyer meets one explanation and not
 *  three variants of it. */
export const CONVERSION_NOTE =
  "Расчёты через Robokassa проводятся в рублях. Итоговая рублёвая сумма " +
  "определяется платёжной системой по её курсу на момент оплаты и " +
  "показывается покупателю до подтверждения платежа.";

/** How long we take to decide on a refund and send it to the payment system.
 *  Stated in both the offer and the refund terms, from here, for the same
 *  reason the price is. */
export const REFUND_DAYS = "5 рабочих дней";
