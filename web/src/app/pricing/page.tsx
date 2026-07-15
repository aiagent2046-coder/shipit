"use client";

import Link from "next/link";
import { TELEGRAM_BOT_USERNAME } from "@/lib/api";
import { useApiKey } from "@/components/providers";
import { UsdtCheckout } from "@/components/UsdtCheckout";

interface Row {
  label: string;
  free: string;
  pro: string;
  // Honest note: is this entitlement actually enforced by the backend today?
  enforced: boolean;
}

// Sourced from app/accounts.py. Only the daily audit limit is actually
// enforced today (via the rate limiter). The other two are returned in the
// entitlements payload but gate nothing yet — we say so rather than oversell.
const ROWS: Row[] = [
  {
    label: "Audits per day",
    free: "5",
    pro: "100",
    enforced: true,
  },
  {
    label: "Private repositories",
    free: "—",
    pro: "Planned",
    enforced: false,
  },
  {
    label: "Priority queue",
    free: "—",
    pro: "Planned",
    enforced: false,
  },
  {
    label: "Full HTML report",
    free: "Yes",
    pro: "Yes",
    enforced: true,
  },
  {
    label: "Severity-scored findings",
    free: "Yes",
    pro: "Yes",
    enforced: true,
  },
];

export default function PricingPage() {
  const { account } = useApiKey();
  const isPro = account?.tier === "pro";
  const telegramConfigured = TELEGRAM_BOT_USERNAME.length > 0;

  return (
    <div className="mx-auto max-w-4xl px-4 py-10">
      <Link href="/" className="text-sm text-muted hover:text-text">
        ← Back to audit
      </Link>

      <header className="mt-6">
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
          Upgrade to Pro
        </h1>
        <p className="mt-2 max-w-2xl text-muted">
          The audit itself is free. Pro raises your daily audit limit — pay
          once with Telegram Stars or USDT and unlock a Pro API key.
        </p>
        {isPro && (
          <p className="mt-3 inline-block rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-sm text-accent">
            The key saved in this browser is already Pro. You&apos;re all set.
          </p>
        )}
      </header>

      {/* Tier comparison */}
      <section className="mt-8 overflow-hidden rounded-xl border border-border bg-elevated">
        <div className="grid grid-cols-3 border-b border-border bg-surface text-sm font-medium">
          <div className="px-4 py-3 text-muted">Feature</div>
          <div className="px-4 py-3">Free</div>
          <div className="px-4 py-3 text-accent">Pro</div>
        </div>
        {ROWS.map((r) => (
          <div
            key={r.label}
            className="grid grid-cols-3 border-b border-border text-sm last:border-b-0"
          >
            <div className="px-4 py-3 text-muted">
              {r.label}
              {!r.enforced && (
                <span className="ml-2 rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted">
                  not enforced yet
                </span>
              )}
            </div>
            <div className="px-4 py-3 font-mono">{r.free}</div>
            <div className="px-4 py-3 font-mono">{r.pro}</div>
          </div>
        ))}
      </section>

      <p className="mt-3 text-xs text-muted">
        Honesty note: today the backend only enforces the daily audit limit.
        &ldquo;Private repositories&rdquo; and &ldquo;Priority queue&rdquo; are
        returned in the account entitlements but don&apos;t gate anything yet —
        they&apos;re on the roadmap, not live features.
      </p>

      {/* Payment options */}
      <section className="mt-10 grid gap-5 md:grid-cols-2">
        {/* Telegram Stars */}
        <div className="rounded-xl border border-border bg-elevated p-5">
          <h3 className="text-lg font-semibold">Pay with Telegram Stars</h3>
          <p className="mt-1 text-sm text-muted">
            Checkout runs inside the Telegram bot. Open it, then use the
            /upgrade command to pay with Stars and receive your key.
          </p>
          {telegramConfigured ? (
            <a
              href={`https://t.me/${TELEGRAM_BOT_USERNAME}`}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-4 inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 font-medium text-accent-fg hover:opacity-90"
            >
              Open @{TELEGRAM_BOT_USERNAME} in Telegram ↗
            </a>
          ) : (
            <div className="mt-4 rounded-md border border-high/40 bg-high/10 p-3 text-sm text-high">
              The Telegram bot username isn&apos;t configured for this site.
              Set <code className="font-mono">NEXT_PUBLIC_TELEGRAM_BOT_USERNAME</code>{" "}
              in the frontend&apos;s environment to enable this button.
            </div>
          )}
        </div>

        {/* USDT / TRC20 */}
        <UsdtCheckout />
      </section>

      <p className="mt-8 text-center text-sm text-muted">
        Already paid?{" "}
        <span>Paste your key using the “I have a key” button in the header.</span>
      </p>
    </div>
  );
}
