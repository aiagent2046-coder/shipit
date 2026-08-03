"use client";

import { useEffect, useState } from "react";
import { getBillingDetails } from "@/lib/api";
import type { BankDetails } from "@/lib/types";

/**
 * The requisites table on /payment-details.
 *
 * Fetched from GET /v1/billing/details rather than baked into the build, so
 * the backend env stays the single source and rotating the card needs no
 * frontend deploy. Three states, and the failed one matters: a payer who came
 * here specifically for SWIFT/IBAN must be told the details are unavailable
 * and where to ask, not left staring at an empty page.
 */
export function PaymentRequisites() {
  const [bank, setBank] = useState<BankDetails | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getBillingDetails()
      .then((d) => {
        if (cancelled) return;
        setBank(d.bank);
        setFailed(d.bank === null);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (failed) {
    return (
      <p className="mt-6 rounded-md border border-border bg-surface p-4 text-sm text-muted">
        The payment details couldn&apos;t be loaded right now. Email{" "}
        <a
          href="mailto:support@drydock.co"
          className="text-accent underline underline-offset-2 hover:opacity-80"
        >
          support@drydock.co
        </a>{" "}
        and we&apos;ll send them to you.
      </p>
    );
  }

  if (!bank) {
    return (
      <p className="mt-6 text-sm text-muted" aria-live="polite">
        Loading payment details…
      </p>
    );
  }

  return (
    <dl className="mt-6 divide-y divide-border rounded-lg border border-border">
      <Requisite label="Card" value={bank.card} mono />
      <Requisite label="Bank" value={bank.bank_name} />
      <Requisite label="SWIFT / BIC" value={bank.swift} mono />
      <Requisite label="Beneficiary" value={bank.beneficiary} />
      <Requisite label="Account / IBAN" value={bank.account} mono />
      <Requisite label="Beneficiary address" value={bank.address} />
    </dl>
  );
}

function Requisite({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked; the value is selectable on the page anyway */
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 p-3 sm:flex-nowrap">
      <dt className="w-44 shrink-0 text-sm text-muted">{label}</dt>
      <dd
        className={`min-w-0 flex-1 break-all text-sm ${mono ? "font-mono" : ""}`}
      >
        {value}
      </dd>
      <button
        type="button"
        onClick={copy}
        className="shrink-0 rounded border border-border px-2 py-0.5 text-xs text-muted hover:text-text"
      >
        {copied ? "✓" : "Copy"}
      </button>
    </div>
  );
}
