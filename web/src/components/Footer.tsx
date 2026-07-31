"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getBillingDetails } from "@/lib/api";
import type { BankDetails } from "@/lib/types";

// Support contacts. Static on purpose: unlike the bank requisites these are
// brand addresses that change with the brand, not with the operator's banking,
// so a rebuild is the right cost for changing them.
const SUPPORT_EMAILS = ["support@drydock.co", "info@drydock.co", "email@drydock.co"];
const SUPPORT_TELEGRAM = "drydocksupport_bot";

/**
 * Site footer: support contacts plus the full payment requisites.
 *
 * The requisites live here rather than on the checkout page by design. The
 * checkout shows one thing — the card number to copy — and a payer whose bank
 * insists on SWIFT/IBAN/beneficiary scrolls down for the rest. Same details,
 * one source: GET /v1/billing/details, so rotating the card is a backend env
 * change with no frontend rebuild.
 *
 * Client-side fetch, and failure is silent: an unreachable backend or an
 * unconfigured deployment renders the footer without the requisites block
 * rather than an error. A footer must never be the thing that breaks a page.
 */
export function Footer() {
  const [bank, setBank] = useState<BankDetails | null>(null);

  useEffect(() => {
    let cancelled = false;
    getBillingDetails()
      .then((d) => {
        if (!cancelled) setBank(d.bank);
      })
      .catch(() => {
        /* no requisites block; not worth showing an error in a footer */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <footer className="mt-16 border-t border-border">
      <div className="mx-auto max-w-5xl px-4 py-8 text-sm text-muted">
        <div className="grid gap-8 sm:grid-cols-2">
          <section>
            <h2 className="font-medium text-text">Contact</h2>
            <ul className="mt-2 space-y-1">
              {SUPPORT_EMAILS.map((email) => (
                <li key={email}>
                  <a
                    href={`mailto:${email}`}
                    className="transition-colors hover:text-text"
                  >
                    {email}
                  </a>
                </li>
              ))}
              <li>
                <a
                  href={`https://t.me/${SUPPORT_TELEGRAM}`}
                  target="_blank"
                  rel="noreferrer"
                  className="transition-colors hover:text-text"
                >
                  @{SUPPORT_TELEGRAM}
                </a>
              </li>
            </ul>
          </section>

          {bank && (
            <section>
              <h2 className="font-medium text-text">Payment details</h2>
              <p className="mt-2 text-xs">
                Full requisites behind the card shown at checkout. You only need
                the card number to pay.
              </p>
              <dl className="mt-2 space-y-1">
                <Requisite label="Card" value={bank.card} mono />
                <Requisite label="Bank" value={bank.bank_name} />
                <Requisite label="SWIFT / BIC" value={bank.swift} mono />
                <Requisite label="Beneficiary" value={bank.beneficiary} />
                <Requisite label="Account / IBAN" value={bank.account} mono />
                <Requisite label="Address" value={bank.address} />
              </dl>
            </section>
          )}
        </div>

        <div className="mt-8 flex flex-col items-center justify-between gap-3 border-t border-border pt-6 sm:flex-row">
          <span>© {new Date().getFullYear()} Drydock</span>
          <nav className="flex items-center gap-4">
            <Link href="/pricing" className="transition-colors hover:text-text">
              Pricing
            </Link>
            <Link href="/privacy" className="transition-colors hover:text-text">
              Privacy
            </Link>
            <Link href="/terms" className="transition-colors hover:text-text">
              Terms
            </Link>
          </nav>
        </div>
      </div>
    </footer>
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
  return (
    <div className="flex flex-wrap gap-x-2">
      <dt className="shrink-0">{label}:</dt>
      <dd className={`break-all text-text ${mono ? "font-mono" : ""}`}>
        {value}
      </dd>
    </div>
  );
}
