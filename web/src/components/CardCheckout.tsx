"use client";

import { useState } from "react";
import type { PayerContact } from "@/lib/api";
import { ApiError, createFixpackCardPayment } from "@/lib/api";
import { formatMoney } from "@/lib/format";
import {
  contactGiven,
  LocaleField,
  PayerInput,
  usePayerLocale,
} from "./PayerFields";
import { Spinner } from "./Spinner";
import { SupportEmail } from "./SupportEmail";

/**
 * Paying for a Fix Pack by card, through ЮKassa.
 *
 * THE BUTTON THIS PRODUCT DID NOT HAVE. The ЮKassa rail shipped working and
 * verified end to end — created, paid, notified, delivered — with nothing on
 * the storefront that reached it. Every visitor was offered a card number to
 * transfer to by hand and a wait for a person to confirm it. ЮMoney's review
 * said as much in one line: "нет возможности что-либо добавить в корзину /
 * оплатить".
 *
 * WHAT THIS COMPONENT DOES AND DOES NOT TOUCH. It collects a name, an email
 * and a language, asks our backend to open a payment, and navigates to the URL
 * that comes back. No card number is typed here, ever: the card is entered on
 * ЮKassa's own page, so nothing on this origin sees a PAN and nothing about
 * this form is in PCI scope. That is also why there is no "processing" state
 * to resume — the buyer leaves.
 *
 * WHY THE EMAIL IS REQUIRED. Two reasons, and only one of them is ours. It is
 * where the confirmation goes, since the buyer may close the tab before the
 * notification lands; and a 54-ФЗ receipt has to be sent to somebody, so a
 * shop configured to issue them cannot open a payment without it.
 */
export function CardCheckout({
  auditId,
  returnToken,
  amount,
  currency,
}: {
  auditId: string;
  /** The audit's access token, so the payer returns to a page they can read. */
  returnToken: string | null;
  amount: string;
  currency: string;
}) {
  const [payerName, setPayerName] = useState("");
  const [payerEmail, setPayerEmail] = useState("");
  const [payerLocale, setPayerLocale] = usePayerLocale();
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ready = contactGiven(payerName, payerEmail);

  async function pay() {
    setStarting(true);
    setError(null);
    try {
      const payer: PayerContact = {
        payer_name: payerName,
        payer_email: payerEmail,
        payer_locale: payerLocale,
      };
      const payment = await createFixpackCardPayment(
        auditId,
        payer,
        returnToken,
      );
      // Navigating away, so `starting` is deliberately left true: clearing it
      // would flash an enabled button under a page that is already leaving.
      window.location.assign(payment.confirmation_url);
    } catch (e) {
      // The backend's own words where it has them. Its refusals here are
      // specific and actionable -- nothing to fix, already bought, paused --
      // and replacing them with "something went wrong" would hide the one
      // sentence that tells the buyer what to do instead.
      // ApiError.message already carries the backend's `detail` (and already
      // replaces the one reason whose detail is operator-authored free text --
      // see parse() in @/lib/api).
      const message =
        e instanceof ApiError
          ? e.message
          : "We couldn't open the payment page. Nothing has been charged — please try again.";
      setError(message);
      setStarting(false);
    }
  }

  return (
    <div className="rounded-xl border border-border bg-surface p-4 sm:p-5">
      <h3 className="text-lg font-semibold">Pay by card</h3>
      <p className="mt-1 text-sm text-muted">
        Card details are entered on ЮKassa&apos;s payment page, not here.
        Your Fix Pack starts the moment the payment goes through — usually a
        few seconds.
      </p>

      <div className="mt-4 space-y-2">
        <PayerInput
          label="Your name"
          type="text"
          autoComplete="name"
          placeholder="Ada Lovelace"
          value={payerName}
          onChange={setPayerName}
          disabled={starting}
        />
        <PayerInput
          label="Your email"
          type="email"
          autoComplete="email"
          placeholder="you@example.com"
          value={payerEmail}
          onChange={setPayerEmail}
          disabled={starting}
        />
        <LocaleField
          value={payerLocale}
          onChange={setPayerLocale}
          disabled={starting}
        />
        <p className="text-xs text-muted">
          We email you when the payment goes through, and if anything is ever
          refunded. Your receipt goes to the same address.
        </p>
      </div>

      <button
        type="button"
        onClick={pay}
        disabled={starting || !ready}
        className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 font-medium text-accent-fg hover:opacity-90 disabled:opacity-60"
      >
        {starting ? (
          <>
            <Spinner /> Opening the payment page…
          </>
        ) : (
          <>Pay {formatMoney(amount, currency)} by card</>
        )}
      </button>

      {/* The figure on the button is the fetched one, not a literal: a number
          typed into this file is how a page starts contradicting what checkout
          charges. */}
      <p className="mt-2 text-center text-xs text-muted">
        One payment. Not a subscription, and nothing recurs.
      </p>

      {error && (
        <div
          role="alert"
          className="mt-3 rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical"
        >
          <p>{error}</p>
          <p className="mt-1 text-muted">
            If this keeps happening, email <SupportEmail /> and we&apos;ll sort
            it out.
          </p>
        </div>
      )}
    </div>
  );
}
