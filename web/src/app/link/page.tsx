"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ApiError, getBankTransferInvoice } from "@/lib/api";
import type { BankTransferStatus } from "@/lib/types";
import { ProCompleted } from "@/components/BankTransferCheckout";
import { Spinner } from "@/components/Spinner";

/**
 * Collect a Pro key with the order reference, after the checkout tab is gone.
 *
 * A bank transfer is confirmed by a human, hours or days after the payer
 * pressed "I've paid". By then the tab that started the order is usually
 * closed, and the key is minted on first ask and revealed exactly once
 * (deliver_key_once in app/billing). Whoever asks first gets it: that tab, this
 * page, or the bot.
 *
 * Every other door out of that situation goes through Telegram -- /link with
 * the reference, /mykey, /rotatekey. That is fine for the audience that already
 * lives there and useless for the one this product is sold to: an indie
 * developer who paid by card and has no reason to have installed a chat app to
 * buy a code review. This page is the same door on the web.
 *
 * It adds no API surface. GET /v1/billing/bank-transfer/{reference} is already
 * public and already reveals the key on a completed invoice -- it is what the
 * checkout page polls. This only gives a payer a way to type their reference
 * into it. Worth stating because it also means this page is not what would make
 * reference codes worth guessing: that endpoint carries no rate limit today,
 * which is a real gap and a separate change, not a reason to leave payers with
 * no door.
 *
 * Bank transfer only. USDT recovery keys off the transaction hash, which the
 * payer always has from their wallet, and only the bot accepts it; the HTTP
 * side is keyed by an invoice id that vanishes with the same tab. Adding a
 * tx-hash claim endpoint is its own change, so this page says so rather than
 * pretending to cover it.
 */

const REFERENCE_PREFIX = "DRY-";
const BODY_LEN = 6;

/**
 * Accept what people actually paste: lowercase, a missing prefix, stray spaces
 * or extra dashes. Deliberately does NOT try to repair characters -- the code
 * alphabet excludes 0, 1, I and O so that they cannot be misread, and guessing
 * that a typed "O" meant something else would be inventing a correction.
 */
function normalizeReference(raw: string): string {
  const body = raw
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/^DRY-?/, "")
    .replace(/-/g, "");
  return `${REFERENCE_PREFIX}${body}`;
}

function isPlausible(reference: string): boolean {
  return reference.length === REFERENCE_PREFIX.length + BODY_LEN;
}

type State =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "not_found" }
  | { kind: "error"; message: string }
  | { kind: "found"; status: BankTransferStatus };

export default function LinkPage() {
  const [input, setInput] = useState("");
  const [state, setState] = useState<State>({ kind: "idle" });
  const [copied, setCopied] = useState<string | null>(null);

  const copy = useCallback(async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      setTimeout(() => setCopied(null), 2000);
    } catch {
      /* clipboard unavailable — the code is on screen to select by hand */
    }
  }, []);

  const lookup = useCallback(async (raw: string) => {
    const reference = normalizeReference(raw);
    setState({ kind: "loading" });
    try {
      setState({ kind: "found", status: await getBankTransferInvoice(reference) });
    } catch (e) {
      // A 404 is the ordinary answer to a wrong code, not a failure worth a red
      // box. Keyed on ApiError.status, not on the message text: this endpoint's
      // 404 detail reads "no bank transfer invoice with this reference, or
      // persistence isn't configured on this deployment", which contains
      // neither "404" nor "not found". Matching on wording therefore sent every
      // mistyped code down the error path and showed the payer a backend note
      // about persistence, while the panel written for exactly this case never
      // rendered at all.
      if (e instanceof ApiError && e.status === 404) {
        setState({ kind: "not_found" });
        return;
      }
      setState({
        kind: "error",
        message:
          e instanceof Error && e.message
            ? e.message
            : "Could not reach the server. Try again in a moment.",
      });
    }
  }, []);

  // Read ?ref= from the URL directly rather than through useSearchParams, which
  // would pull this otherwise-static page into a Suspense boundary for one
  // optional query parameter. Runs once, on mount, client-side only.
  useEffect(() => {
    const ref = new URLSearchParams(window.location.search).get("ref");
    if (!ref) return;
    setInput(ref);
    void lookup(ref);
  }, [lookup]);

  const normalized = normalizeReference(input);
  const ready = isPlausible(normalized);

  return (
    <div className="mx-auto max-w-2xl px-4 py-10">
      <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
        Find your Pro key
      </h1>
      <p className="mt-3 text-muted">
        Paid by card transfer and closed the tab before your key appeared? Enter
        the order reference you were given at checkout — it looks like{" "}
        <span className="font-mono">DRY-4KQ8ZP</span>.
      </p>

      <form
        className="mt-6 flex flex-wrap items-start gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) void lookup(input);
        }}
      >
        <label className="sr-only" htmlFor="reference">
          Order reference
        </label>
        <input
          id="reference"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="DRY-4KQ8ZP"
          autoComplete="off"
          spellCheck={false}
          className="min-w-[12rem] flex-1 rounded-md border border-border bg-bg px-3 py-2 font-mono text-text outline-hidden focus:border-accent"
        />
        <button
          type="submit"
          disabled={!ready || state.kind === "loading"}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-fg disabled:opacity-50"
        >
          {state.kind === "loading" ? "Checking…" : "Find my key"}
        </button>
      </form>

      {state.kind === "loading" && (
        <div className="mt-6 flex items-center gap-2 text-sm text-muted">
          <Spinner /> Looking up your order…
        </div>
      )}

      {state.kind === "not_found" && (
        <div className="mt-6 rounded-md border border-border p-4 text-sm">
          <p className="font-medium">No order with that reference.</p>
          <p className="mt-2 text-muted">
            Check it against the confirmation you saw at checkout. The code has
            six characters after <span className="font-mono">DRY-</span> and
            never contains the digits 0 or 1, or the letters I or O — those are
            left out so they cannot be misread.
          </p>
        </div>
      )}

      {state.kind === "error" && (
        <div className="mt-6 rounded-md border border-critical p-4 text-sm">
          <p className="font-medium text-critical">Something went wrong.</p>
          <p className="mt-2 text-muted">{state.message}</p>
        </div>
      )}

      {state.kind === "found" && (
        <div className="mt-6 rounded-md border border-border p-4">
          <Found status={state.status} copy={copy} copied={copied} />
        </div>
      )}

      <section className="mt-10 border-t border-border pt-6 text-sm text-muted">
        <h2 className="font-medium text-text">Paid with USDT instead?</h2>
        <p className="mt-2">
          Recovery for a crypto payment uses your transaction hash, which is in
          your wallet rather than on a page you might have closed. Send{" "}
          <span className="font-mono">/link &lt;tx_hash&gt;</span> to{" "}
          <a
            href="https://t.me/drydocksupport_bot"
            className="text-accent underline"
          >
            @drydocksupport_bot
          </a>
          .
        </p>
        <p className="mt-4">
          Still stuck? Email{" "}
          <a href="mailto:support@drydock.co" className="text-accent underline">
            support@drydock.co
          </a>{" "}
          with your reference, or go back to{" "}
          <Link href="/pricing" className="text-accent underline">
            pricing
          </Link>
          .
        </p>
      </section>
    </div>
  );
}

function Found({
  status,
  copy,
  copied,
}: {
  status: BankTransferStatus;
  copy: (text: string, label: string) => void;
  copied: string | null;
}) {
  if (status.status === "completed") {
    if (status.product === "pro_tier") {
      // Same component the checkout renders, so "shown once, never again" is
      // worded identically in both places.
      return <ProCompleted completed={status} copy={copy} copied={copied} />;
    }
    return (
      <>
        <p className="font-semibold text-accent">This order is confirmed.</p>
        <p className="mt-2 text-sm text-muted">
          It was a Fix Pack, not a Pro subscription, so there is no API key for
          it — the fix arrives as a pull request on your repository.{" "}
          {status.audit_id ? (
            <Link
              href={`/audit/${status.audit_id}`}
              className="text-accent underline"
            >
              Open the audit
            </Link>
          ) : (
            "Open the audit page you bought it from to see it."
          )}
        </p>
      </>
    );
  }

  // pending and expired are the same situation for the payer: the money has not
  // been confirmed yet. Expiry is cosmetic on purpose -- confirm() ignores it,
  // so a transfer that took nine days is still a transfer, and telling someone
  // their paid order died would be both wrong and expensive.
  return (
    <>
      <p className="font-semibold">We haven&apos;t confirmed this transfer yet.</p>
      <p className="mt-2 text-sm text-muted">
        Confirmation is manual and usually lands within a business day. Nothing
        is lost while you wait — come back to this page with the same reference,
        or bookmark it.
      </p>
      {status.status === "pending" && status.amount && (
        <p className="mt-3 text-sm text-muted">
          Expecting{" "}
          <span className="font-mono text-text">
            {status.amount} {status.currency}
          </span>
          . The exact kopecks are what identify your order, so the amount has to
          match to the cent.
        </p>
      )}
      {status.status === "expired" && (
        <p className="mt-3 text-sm text-muted">
          The quote shown at checkout has gone stale, which changes nothing
          about a transfer already sent: it can still be confirmed.
        </p>
      )}
    </>
  );
}
