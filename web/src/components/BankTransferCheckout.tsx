"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import type { BankTransferInvoice, BankTransferStatus } from "@/lib/types";
import type { PayerContact } from "@/lib/api";
import {
  ApiError,
  createBankTransferInvoice,
  getBankTransferInvoice,
  reportBankTransferPaid,
} from "@/lib/api";
import { useApiKey } from "./providers";
import { Field } from "./UsdtCheckout";
import { Spinner } from "./Spinner";

type CompletedStatus = Extract<BankTransferStatus, { status: "completed" }>;

interface CopyHelpers {
  copy: (text: string, label: string) => void;
  copied: string | null;
}

// Slower than the USDT poll (8s): confirmation here is a human reading a bank
// statement, which lands hours or days later, not seconds.
const POLL_MS = 20_000;

/**
 * The shared bank-transfer flow, the manual-confirmation counterpart to
 * UsdtCheckout: create an invoice, show the bank details plus the reference
 * code to quote, offer an "I've paid" button that pages the operator, then
 * poll until they confirm.
 *
 * Two things differ from every other provider here and drive the whole UI:
 *
 *  - Nothing is automatic. The operator finds the transfer in their banking
 *    app by hand, so the wait is measured in business days and the page says
 *    so rather than showing a countdown that implies minutes.
 *  - The payer is shown ONE thing to act on: the card number. A card-to-card
 *    transfer has no payment-reference field, so quoting a code through the
 *    bank is impossible and the operator matches by the payer's name and
 *    email instead — which is why both inputs below are required, not
 *    optional. The full requisites behind the card live on /payment-details
 *    for the rare payer whose bank asks for SWIFT/IBAN; this screen stays a
 *    card number and a Copy button.
 *
 * "I've paid" is a notification, not a claim on anything: it grants no access
 * and moves no state, so pressing it without paying accomplishes nothing.
 */
export function BankTransferCheckout({
  title = "Pay by card",
  description,
  createInvoice,
  renderCompleted,
}: {
  title?: string;
  description: React.ReactNode;
  createInvoice: (payer: PayerContact) => Promise<BankTransferInvoice>;
  renderCompleted: (
    completed: CompletedStatus,
    helpers: CopyHelpers,
  ) => React.ReactNode;
}) {
  const [invoice, setInvoice] = useState<BankTransferInvoice | null>(null);
  const [status, setStatus] = useState<BankTransferStatus | null>(null);
  const [creating, setCreating] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [reported, setReported] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [payerName, setPayerName] = useState("");
  const [payerEmail, setPayerEmail] = useState("");
  // The backend rejects a blank name or an email with no "@" (422). Mirroring
  // exactly that here keeps the button honest rather than letting the payer
  // submit into a validation error.
  const contactReady =
    payerName.trim().length > 0 && payerEmail.trim().includes("@");
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => () => stopPolling(), [stopPolling]);

  async function start() {
    setCreating(true);
    setError(null);
    setStatus(null);
    setReported(false);
    try {
      const inv = await createInvoice({
        payer_name: payerName,
        payer_email: payerEmail,
      });
      setInvoice(inv);
      poll(inv.reference);
    } catch (e) {
      setError(
        e instanceof ApiError
          ? e.reason === "bank_transfer_not_configured" ||
            e.reason === "not_persisted"
            ? "Card payment isn't configured on the backend yet. Try another payment method, or contact support."
            : e.message
          : "Could not create an invoice.",
      );
    } finally {
      setCreating(false);
    }
  }

  function poll(reference: string) {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const s = await getBankTransferInvoice(reference);
        setStatus(s);
        // Only "completed" stops the poll. An expired bank invoice is NOT
        // terminal — the operator can still confirm a transfer that took nine
        // days, so we keep watching rather than tell the payer to start over.
        if (s.status === "completed") stopPolling();
      } catch {
        /* transient; keep polling */
      }
    }, POLL_MS);
  }

  async function reportPaid(reference: string) {
    setReporting(true);
    setError(null);
    try {
      await reportBankTransferPaid(reference);
      // Tracked in this component only, deliberately: recording "awaiting
      // confirmation" server-side would move the payment off `pending`, and
      // the confirmation path only accepts a pending row.
      setReported(true);
    } catch (e) {
      setError(
        e instanceof ApiError
          ? e.message
          : "Could not notify the operator. Your transfer is unaffected — try again shortly.",
      );
    } finally {
      setReporting(false);
    }
  }

  const copy = useCallback(async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }, []);

  const completed = status?.status === "completed" ? status : null;

  return (
    <div className="rounded-xl border border-border bg-elevated p-5">
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="mt-1 text-sm text-muted">{description}</p>

      {!invoice && (
        <>
          {/* Required, and required for a concrete reason: a card transfer
              arrives with nothing on it but the sender's name, so this is how
              the operator knows which order the money belongs to. */}
          <div className="mt-4 space-y-2">
            <PayerInput
              label="Your name"
              type="text"
              autoComplete="name"
              placeholder="Exactly as on the sending card"
              value={payerName}
              onChange={setPayerName}
              disabled={creating}
            />
            <PayerInput
              label="Your email"
              type="email"
              autoComplete="email"
              placeholder="you@example.com"
              value={payerEmail}
              onChange={setPayerEmail}
              disabled={creating}
            />
            <p className="text-xs text-muted">
              A card transfer carries no order number, so your name and email
              are how we recognise your payment. Use the name on the card you
              pay from. We don&apos;t email you — this page is where your order
              updates.
            </p>
          </div>

          <button
            type="button"
            onClick={start}
            disabled={creating || !contactReady}
            className="mt-4 flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 font-medium text-accent-fg hover:opacity-90 disabled:opacity-60"
          >
            {creating ? (
              <>
                <Spinner /> Creating invoice…
              </>
            ) : (
              "Show card number"
            )}
          </button>
        </>
      )}

      {error && (
        <p
          className="mt-4 rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical"
          role="alert"
        >
          {error}
        </p>
      )}

      {invoice && !completed && (
        <div className="mt-4 space-y-3">
          {/* The whole point of this screen: one number, one Copy button.
              Everything else here is context, not something to act on. */}
          <div className="rounded-md border border-accent/40 bg-accent/10 p-3">
            <p className="text-xs font-medium text-accent">
              Send exactly {invoice.amount} {invoice.currency} to this card
              {invoice.bank.bank_name ? ` — ${invoice.bank.bank_name}` : ""}
            </p>
            <div className="mt-1 flex items-center justify-between gap-3">
              <code className="break-all font-mono text-xl tracking-wider">
                {invoice.bank.card}
              </code>
              <button
                type="button"
                onClick={() => copy(invoice.bank.card, "card")}
                className="shrink-0 rounded border border-border px-2 py-0.5 text-xs text-muted hover:text-text"
              >
                {copied === "card" ? "✓" : "Copy"}
              </button>
            </div>
            <p className="mt-2 text-xs text-muted">
              Send the exact amount, kopecks included — they identify your order.
              Pay from a card in the name you entered. No comment or reference is
              needed.
            </p>
          </div>

          <Field
            label="Exact amount"
            value={`${invoice.amount} ${invoice.currency}`}
            mono
            onCopy={() => copy(invoice.amount, "amount")}
            copied={copied === "amount"}
          />
          <p className="text-xs text-muted">
            The kopecks are unique to this order — they&apos;re how we spot your
            transfer among others. If your bank charges in another currency it
            converts at its own rate and the figure that arrives will differ;
            that&apos;s fine, we&apos;ll match you by name instead.
          </p>

          {/* Not a payment instruction — the order id, kept visible because
              /link and support both ask for it, and confirmation often lands
              long after this tab is gone. */}
          <Field
            label="Order number"
            value={invoice.reference}
            mono
            onCopy={() => copy(invoice.reference, "reference")}
            copied={copied === "reference"}
          />
          <p className="text-xs text-muted">
            Keep this if you need to reach support about the order, or to claim
            your key from the Telegram bot with{" "}
            <span className="font-mono">/link</span>. You don&apos;t need to put
            it anywhere in the transfer.
          </p>

          <p className="text-xs text-muted">
            Bank needs full requisites (SWIFT / IBAN / beneficiary)? They&apos;re
            on the{" "}
            <Link
              href="/payment-details"
              className="text-accent underline underline-offset-2 hover:opacity-80"
            >
              payment details
            </Link>{" "}
            page.
          </p>

          {reported ? (
            <p className="flex items-center gap-2 rounded-md border border-border bg-surface p-3 text-sm text-muted">
              <Spinner /> Thanks — we&apos;ve been notified and will look for
              your transfer. Confirmation is manual, so allow up to one business
              day. This page updates itself, and you can safely close it.
            </p>
          ) : (
            <button
              type="button"
              onClick={() => reportPaid(invoice.reference)}
              disabled={reporting}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 font-medium text-accent-fg hover:opacity-90 disabled:opacity-60"
            >
              {reporting ? (
                <>
                  <Spinner /> Notifying…
                </>
              ) : (
                "I've paid"
              )}
            </button>
          )}

          {status?.status === "expired" && (
            <p className="rounded-md border border-high/40 bg-high/10 p-3 text-xs text-high">
              This quote is more than a week old. Your transfer can still be
              confirmed if it arrives — nothing is lost — but if you haven&apos;t
              paid yet, contact support to re-check the amount and the card
              number first.
            </p>
          )}
        </div>
      )}

      {completed && renderCompleted(completed, { copy, copied })}
    </div>
  );
}

// The editable twin of UsdtCheckout's Field: same bordered row, same muted
// label on the left and right-aligned value, so the pre-payment inputs and the
// post-payment bank details read as one list rather than two designs.
function PayerInput({
  label,
  type,
  autoComplete,
  placeholder,
  value,
  onChange,
  disabled,
}: {
  label: string;
  type: "text" | "email";
  autoComplete: string;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  return (
    <label className="flex items-center justify-between gap-3 rounded-md border border-border bg-surface px-3 py-2 text-sm focus-within:border-accent">
      <span className="shrink-0 text-muted">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoComplete={autoComplete}
        disabled={disabled}
        maxLength={200}
        className="w-full min-w-0 bg-transparent text-right outline-none disabled:opacity-60"
      />
    </label>
  );
}

/**
 * The Pro-tier card-payment card used on /pricing. Once the operator confirms,
 * reveals + lets you save the returned API key — the same one-shot delivery as
 * the USDT card, and it matters more here: confirmation lands hours later, when
 * this tab is usually long gone. Telegram /link with the order number is the
 * recovery door for that case.
 */
export function ProBankTransferCheckout() {
  return (
    <BankTransferCheckout
      description={
        <>
          Copy the card number and pay from your banking app. Your Pro key
          unlocks once we&apos;ve seen the money — usually within a business day.
        </>
      }
      createInvoice={createBankTransferInvoice}
      renderCompleted={(completed, { copy, copied }) =>
        completed.product === "pro_tier" ? (
          <ProCompleted completed={completed} copy={copy} copied={copied} />
        ) : null
      }
    />
  );
}

function ProCompleted({
  completed,
  copy,
  copied,
}: {
  completed: Extract<CompletedStatus, { product: "pro_tier" }>;
  copy: (text: string, label: string) => void;
  copied: string | null;
}) {
  const { setKey } = useApiKey();
  const [saved, setSaved] = useState(false);
  return (
    <div className="mt-4 rounded-md border border-accent/40 bg-accent/10 p-4">
      <p className="font-semibold text-accent">
        Transfer confirmed — you&apos;re Pro.
      </p>
      {completed.api_key ? (
        <>
          <p className="mt-2 text-sm text-muted">Your API key:</p>
          <code className="mt-1 block break-all rounded bg-surface p-2 font-mono text-sm">
            {completed.api_key}
          </code>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => copy(completed.api_key!, "key")}
              className="rounded-md border border-border px-3 py-1.5 text-sm hover:border-accent"
            >
              {copied === "key" ? "Copied!" : "Copy key"}
            </button>
            <button
              type="button"
              onClick={async () => {
                await setKey(completed.api_key!);
                setSaved(true);
              }}
              className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg"
            >
              {saved ? "Saved to this browser" : "Use this key now"}
            </button>
          </div>
          <p className="mt-2 text-xs text-muted">
            Keep it secret — anyone with it has your pro access.
          </p>
        </>
      ) : (
        <p className="mt-2 text-sm text-muted">
          This key was already delivered once — on this page, or to Telegram if
          you claimed it with <span className="font-mono">/link</span>. For
          security it is shown only once and is never stored, so it can&apos;t be
          shown again. Lost it? Send{" "}
          <span className="font-mono">/rotatekey</span> to the bot for a new key,
          or contact the operator with reference{" "}
          <span className="font-mono">{completed.reference}</span>.
        </p>
      )}
    </div>
  );
}
