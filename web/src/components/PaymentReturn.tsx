"use client";

import { useEffect, useState } from "react";
import { getBillingDetails } from "@/lib/api";

/**
 * What a buyer sees on the page ЮKassa returns them to.
 *
 * WITHOUT THIS THEY SEE NOTHING NEW. The grant is decided server-side by a
 * notification that lands seconds after the redirect, so the page they come
 * back to still shows the checkout form. Somebody who has just typed their
 * card in has no way to tell whether it worked.
 *
 * `paid` IS A MARKER, NOT A FACT. It arrives in the buyer's own browser and
 * anyone can type it, so it may change what this says and never what anything
 * does — and what it says has to stay true for someone who added the parameter
 * by hand. Hence "if the payment went through" rather than congratulations.
 *
 * THE TELEGRAM BUTTON IS THE ONLY WAY TO OFFER THAT CHANNEL. The Bot API
 * cannot message a person who has never written to the bot, so a "your
 * @username" field in the checkout would collect something unusable. One tap
 * on a deep link is what establishes the chat, and the order reference in the
 * payload is what tells the bot which order it belongs to.
 */
export function PaymentReturn({ order }: { order: string | null }) {
  const [bot, setBot] = useState<string | null>(null);

  useEffect(() => {
    // Only for a buyer who is actually coming back. Everyone else reading an
    // audit has no use for a bot name, and no reason to spend a request on it.
    if (!order) return;
    let cancelled = false;
    getBillingDetails()
      .then((d) => {
        if (!cancelled) setBot(d.telegram_bot ?? null);
      })
      .catch(() => {
        // A missing button is the right failure here: the customer still gets
        // the email, and an error box about a convenience channel on top of a
        // payment they just made would read as something having gone wrong.
      });
    return () => {
      cancelled = true;
    };
  }, [order]);

  return (
    <div className="mt-8 rounded-xl border border-accent/40 bg-accent/10 p-4">
      <p className="font-semibold text-accent">
        You&apos;ve come back from the payment page.
      </p>
      <p className="mt-1 text-sm text-muted">
        If the payment went through, your Fix Pack starts on its own — usually
        within a few seconds — and its progress appears below. You don&apos;t
        need to pay again or keep this tab open; we email you either way.
      </p>

      {order && bot && (
        <a
          href={`https://t.me/${bot}?start=${order}`}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-3 inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-sm hover:border-accent"
        >
          Get this order&apos;s updates in Telegram
        </a>
      )}
      {order && (
        <p className="mt-2 text-xs text-muted">
          Your order number is <span className="font-mono">{order}</span>. Keep
          it — it&apos;s how support finds this payment.
        </p>
      )}
    </div>
  );
}

/**
 * An order reference, or null for anything that is not one.
 *
 * The value goes into a URL the page invites someone to tap, so it is checked
 * against the shape the backend mints rather than passed through: the alphabet
 * is bank_transfer._REFERENCE_ALPHABET, which drops the characters people
 * misread (0/O, 1/I/L, U).
 */
export function orderFromQuery(raw: string | null): string | null {
  const value = (raw ?? "").trim().toUpperCase();
  return /^DRY-[2-9A-HJ-NP-Z]{6}$/.test(value) ? value : null;
}
