import type { Metadata } from "next";
import Link from "next/link";
import { PaymentRequisites } from "@/components/PaymentRequisites";

/**
 * The full bank requisites, on their own page and out of the search index.
 *
 * Checkout shows one thing — the card number to copy — because that is all a
 * payer needs. This page exists for the minority whose bank asks for
 * SWIFT/IBAN/beneficiary, and the footer links here rather than carrying the
 * details on every page.
 *
 * noindex is the reason for the split. These are a private individual's real
 * banking details; publishing them where a payer can find them is intended,
 * having them indexed, snippeted and archived across the web is not. `follow`
 * stays on: the outgoing links here are ordinary site navigation.
 */
export const metadata: Metadata = {
  title: "Payment details — Drydock",
  description:
    "Full bank requisites for paying Drydock by card transfer, for payers whose bank asks for SWIFT, IBAN or beneficiary details.",
  robots: { index: false, follow: true },
};

export default function PaymentDetailsPage() {
  return (
    <div className="mx-auto max-w-2xl px-4 py-10">
      <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
        Payment details
      </h1>
      <p className="mt-3 text-muted">
        You only need the card number to pay, and checkout shows it to you when
        you start an order. These are the full requisites behind that card, for
        the case where your bank asks for SWIFT, IBAN or a beneficiary name.
      </p>

      <PaymentRequisites />

      <section className="mt-10 border-t border-border pt-6">
        <h2 className="font-medium">Before you pay</h2>
        <ul className="mt-3 space-y-2 text-sm text-muted">
          <li>
            Start the order on the{" "}
            <Link
              href="/pricing"
              className="text-accent underline underline-offset-2 hover:opacity-80"
            >
              pricing page
            </Link>{" "}
            first. It gives you the exact amount to send — the kopecks are
            unique to your order and are how we recognise your transfer.
          </li>
          <li>
            Quote your order number in the transfer&apos;s comment field if your
            bank offers one. Not every bank does for a card-to-card transfer, so
            also pay from a card in the name you entered at checkout — that is
            the other half of how we match the payment.
          </li>
          <li>
            Confirmation is manual. Allow up to one business day, and the order
            page updates itself — you don&apos;t need to keep it open.
          </li>
        </ul>
      </section>

      <section className="mt-8">
        <h2 className="font-medium">Questions about a payment</h2>
        <p className="mt-3 text-sm text-muted">
          Email{" "}
          <a
            href="mailto:support@drydock.co"
            className="text-accent underline underline-offset-2 hover:opacity-80"
          >
            support@drydock.co
          </a>{" "}
          or message{" "}
          <a
            href="https://t.me/drydocksupport_bot"
            target="_blank"
            rel="noreferrer"
            className="text-accent underline underline-offset-2 hover:opacity-80"
          >
            @drydocksupport_bot
          </a>{" "}
          with your order number.
        </p>
      </section>
    </div>
  );
}
