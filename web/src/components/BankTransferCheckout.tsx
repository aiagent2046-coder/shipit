"use client";

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
 *  - Nothing is automatic. The operator reads the reference off their bank
 *    statement by hand, so the wait is measured in business days and the page
 *    says so rather than showing a countdown that implies minutes.
 *  - The bank details arrive in the create-invoice RESPONSE, not from build-
 *    time config. They are a private individual's account, so they are never
 *    NEXT_PUBLIC_* and this component never hardcodes or caches them.
 *
 * "I've paid" is a notification, not a claim on anything: it grants no access
 * and moves no state, so pressing it without paying accomplishes nothing.
 */
export function BankTransferCheckout({
  title = "Pay by bank transfer",
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
            ? "Bank transfer isn't configured on the backend yet. Try another payment method, or ask the operator to configure it."
            : e.message
          : "Could not create a bank transfer invoice.",
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
          {/* Optional both in name and in fact: leaving these blank creates a
              perfectly good invoice. Money for this provider lands on a
              private individual's account, so the operator keeps a note of who
              paid for their own books — nothing is ever sent to the address,
              and nothing checks its format. */}
          <div className="mt-4 space-y-2">
            <PayerInput
              label="Your name (optional)"
              type="text"
              autoComplete="name"
              placeholder="Name on the transfer"
              value={payerName}
              onChange={setPayerName}
              disabled={creating}
            />
            <PayerInput
              label="Your email (optional)"
              type="email"
              autoComplete="email"
              placeholder="you@example.com"
              value={payerEmail}
              onChange={setPayerEmail}
              disabled={creating}
            />
            <p className="text-xs text-muted">
              Only so the operator can tie the transfer to a person in their
              records. Both can be left empty, and we don&apos;t email you —
              this page is where your order updates.
            </p>
          </div>

          <button
            type="button"
            onClick={start}
            disabled={creating}
            className="mt-4 flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 font-medium text-accent-fg hover:opacity-90 disabled:opacity-60"
          >
            {creating ? (
              <>
                <Spinner /> Creating invoice…
              </>
            ) : (
              "Get bank details"
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
          <div className="rounded-md border border-accent/40 bg-accent/10 p-3">
            <p className="text-xs font-medium text-accent">
              Payment reference — put this in the transfer&apos;s reference
              field
            </p>
            <div className="mt-1 flex items-center justify-between gap-3">
              <code className="break-all font-mono text-lg tracking-wider">
                {invoice.reference}
              </code>
              <button
                type="button"
                onClick={() => copy(invoice.reference, "reference")}
                className="shrink-0 rounded border border-border px-2 py-0.5 text-xs text-muted hover:text-text"
              >
                {copied === "reference" ? "✓" : "Copy"}
              </button>
            </div>
            <p className="mt-2 text-xs text-muted">
              This code is how your transfer is matched to this order. Without
              it we can&apos;t tell which payment is yours.
            </p>
          </div>

          <Field
            label="Amount"
            value={`${invoice.amount} ${invoice.currency}`}
            mono
            onCopy={() => copy(invoice.amount, "amount")}
            copied={copied === "amount"}
          />
          <p className="text-xs text-muted">
            Charged in {invoice.currency}; your bank converts at its own rate on
            the day of the transfer, so the exact figure that arrives may differ
            slightly. That&apos;s expected — the reference is what matters.
          </p>

          <Field label="Bank" value={invoice.bank.bank_name} />
          <Field label="SWIFT / BIC" value={invoice.bank.swift} mono
            onCopy={() => copy(invoice.bank.swift, "swift")}
            copied={copied === "swift"} />
          <Field label="Beneficiary" value={invoice.bank.beneficiary}
            onCopy={() => copy(invoice.bank.beneficiary, "beneficiary")}
            copied={copied === "beneficiary"} />
          <Field
            label="Account / IBAN"
            value={invoice.bank.account}
            mono
            breakAll
            onCopy={() => copy(invoice.bank.account, "account")}
            copied={copied === "account"}
          />
          <Field label="Beneficiary address" value={invoice.bank.address} breakAll />

          {reported ? (
            <p className="flex items-center gap-2 rounded-md border border-border bg-surface p-3 text-sm text-muted">
              <Spinner /> Thanks — we&apos;ve been notified and will check the
              transfer. Bank transfers usually take 1–3 business days to arrive.
              This page updates itself, and you can safely close it.
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
                "I've sent the transfer"
              )}
            </button>
          )}

          {status?.status === "expired" && (
            <p className="rounded-md border border-high/40 bg-high/10 p-3 text-xs text-high">
              This quote is more than a week old. Your transfer can still be
              confirmed if it arrives — nothing is lost — but if you haven&apos;t
              sent it yet, contact the operator to re-check the amount first.
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
 * The Pro-tier bank-transfer card used on /pricing. Once the operator
 * confirms, reveals + lets you save the returned API key — the same one-shot
 * delivery as the USDT card, and it matters more here: confirmation lands
 * hours or days later, when this tab is usually long gone. Telegram /link with
 * the reference code is the recovery door for that case.
 */
export function ProBankTransferCheckout() {
  return (
    <BankTransferCheckout
      description={
        <>
          Send a normal bank transfer quoting the reference code below. Your Pro
          key unlocks once we&apos;ve seen the money — usually 1–3 business days.
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
