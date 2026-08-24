"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getPricing } from "@/lib/api";
import { formatMoney } from "@/lib/format";
import { FIXPACK_PRICE_RUB } from "@/app/ru/price";
import type { Pricing } from "@/lib/types";

/**
 * The storefront.
 *
 * Rewritten around the Fix Pack. The page it replaced sold Pro: an "Upgrade to
 * Pro" header, a Free-vs-Pro table and a Pro checkout. Two things were wrong
 * with that. It carried no price at all, so the only way to learn what
 * anything cost was to start a checkout; and its table had been stale since
 * the free tier became static-only at 3 audits a day, so it advertised "Free:
 * 5 audits" and "Severity-scored findings: yes" — neither true.
 *
 * Pro is no longer offered here at all. Its one live benefit is a higher daily
 * audit limit, and since free audits are static-only they cost us nothing to
 * run: charging for more of something that is free to serve is not a product.
 * The Pro purchase routes stay reachable for the existing customer and through
 * the bot, they are just not advertised.
 *
 * The price is fetched from the backend that charges it — see getPricing — so
 * an env override on the deployment is reflected here without a rebuild. What
 * it no longer does is render NOTHING when that request is slow or fails. A
 * page whose price can be absent is a page with no price, which is the same
 * defect a payment aggregator rejects a "from 100 ₽" for, and the buyer who
 * came here for one number is the person it fails.
 *
 * The fallback is FIXPACK_PRICE_RUB, the constant the Russian legal pages are
 * built from, which tests/test_ru_legal_pages.py pins against the backend's own
 * default. So it is not "a number typed into this file" -- it is the same
 * number, held to the same source, by a test that fails when they part.
 */

// What the free static scan actually detects today, from app/scan/checks.py
// and the secret rules. Claims here must be things the free tier really
// returns: this page is read by someone deciding whether to trust us.
const FREE_FINDS = [
  "Secrets committed in code or in a tracked .env",
  "A .gitignore that does not cover secret-bearing files",
  "No test suite",
  "No CI workflow",
  "No Dockerfile",
];

// Deliberately explicit about what the free scan does NOT do, because the
// score is the thing people expect and we no longer show one for it.
const FREE_OMITS = [
  "No readiness score out of 10",
  "No review of authentication or access rules",
  "No review of injection risk in your queries",
];

// What the Fix Pack adds on top of the fix itself (#188). Kept as its own list
// rather than folded into FIXPACK_INCLUDES: those items are all things the diff
// does, this one is a separate deliverable that arrives as a link.
const FIXPACK_REVIEW = [
  "A readiness score out of 10",
  "Authentication and access rules reviewed",
  "Injection risk in your queries reviewed",
];

// Everything the paid pull request contains. Each line maps to real generator
// behaviour in app/fixpack/generate.py — nothing aspirational.
const FIXPACK_INCLUDES = [
  // Narrowed from "Each hardcoded secret …", which was false and false at the
  // worst moment — before payment. The Fix Pack plans only from static rule
  // ids (app/fixpack/generate.py, _is_fixable_rule), so a secret that only
  // the deep review spots is reported and left in place. A real customer paid
  // while three CRITICAL findings about a live key sat outside that filter.
  "Each hardcoded secret the static rules detect, replaced with an environment variable reference",
  // Now a real deliverable, not a caveat: the PR carries the list.
  "A list of every finding it does NOT change — including anything the deep review found, which is reported but not rewritten",
  "A committed .env removed from version control, with every variable name preserved in .env.example",
  "A .gitignore that covers .env files and key material",
  "Per-provider instructions for rotating every secret that leaked, because deleting it from code does not make it safe",
  "Your own test suite run against the change before the pull request opens",
];

export default function PricingPage() {
  const [pricing, setPricing] = useState<Pricing | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getPricing()
      .then((p) => {
        if (!cancelled) setPricing(p);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="mx-auto max-w-4xl px-4 py-10">
      <Link href="/" className="text-sm text-muted hover:text-text">
        ← Back to audit
      </Link>

      <header className="mt-6">
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
          You pay for the fix, not the finding
        </h1>
        <p className="mt-3 max-w-2xl text-muted">
          Finding problems is cheap, so we do it for free. Fixing them takes
          real work, and that is the only thing we charge for.
        </p>
      </header>

      <section className="mt-8 grid gap-5 md:grid-cols-2">
        {/* Free */}
        <div className="rounded-xl border border-border bg-elevated p-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="text-lg font-semibold">Audit</h2>
            <p className="font-mono text-2xl font-semibold">Free</p>
          </div>
          <p className="mt-1 text-sm text-muted">
            Three audits a day per IP address. No account, no card, no sign-up.
          </p>

          <p className="mt-4 text-xs font-medium uppercase tracking-wide text-muted">
            Finds
          </p>
          <ul className="mt-2 space-y-1.5 text-sm">
            {FREE_FINDS.map((item) => (
              <li key={item} className="flex gap-2">
                <span aria-hidden="true" className="text-accent">
                  ✓
                </span>
                <span>{item}</span>
              </li>
            ))}
          </ul>

          <p className="mt-4 text-xs font-medium uppercase tracking-wide text-muted">
            Does not include
          </p>
          <ul className="mt-2 space-y-1.5 text-sm text-muted">
            {FREE_OMITS.map((item) => (
              <li key={item} className="flex gap-2">
                <span aria-hidden="true">—</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>

          <Link
            href="/"
            className="mt-5 inline-block rounded-lg border border-border px-4 py-2 text-sm font-medium hover:border-accent hover:text-accent"
          >
            Run an audit
          </Link>
        </div>

        {/* Fix Pack */}
        <div className="rounded-xl border border-accent/40 bg-accent/5 p-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="text-lg font-semibold">Fix Pack</h2>
            {/* A PRICE MUST NOT BE ABLE TO VANISH. This rendered "…" while the
                request was in flight and "—" if it failed, so the one number a
                buyer came for was the one thing on the page that could be
                missing -- and a payment aggregator reviewing the site sees
                exactly the same absence they reject a "от 100 ₽" for.

                The fetched value still wins, so an env override is reflected
                within a request. What changed is the floor: FIXPACK_PRICE_RUB
                is compiled in and pinned by tests/test_ru_legal_pages.py
                against the backend's own default, so the fallback cannot drift
                into advertising a figure the checkout will not charge. */}
            <p className="font-mono text-2xl font-semibold" aria-live="polite">
              {pricing
                ? formatMoney(pricing.fixpack.amount, pricing.fixpack.currency)
                : formatMoney(FIXPACK_PRICE_RUB, "RUB")}
            </p>
          </div>
          <p className="mt-1 text-sm text-muted">
            Per audit, paid once by card. Not a subscription — nothing recurs
            and nothing is stored to charge again.
          </p>
          {failed && (
            <p className="mt-2 text-xs text-critical">
              We couldn&apos;t reach the server to re-check this price just now,
              so the standard one is shown. It is what the checkout charges; if
              you would rather have it confirmed first, email{" "}
              <a
                href="mailto:support@drydock.co"
                className="underline underline-offset-2"
              >
                support@drydock.co
              </a>{" "}
              before you pay anything.
            </p>
          )}

          <p className="mt-4 text-xs font-medium uppercase tracking-wide text-muted">
            You get a pull request containing
          </p>
          <ul className="mt-2 space-y-1.5 text-sm">
            {FIXPACK_INCLUDES.map((item) => (
              <li key={item} className="flex gap-2">
                <span aria-hidden="true" className="text-accent">
                  ✓
                </span>
                <span>{item}</span>
              </li>
            ))}
          </ul>

          <p className="mt-4 text-xs font-medium uppercase tracking-wide text-muted">
            Plus the full review the free scan leaves out
          </p>
          <ul className="mt-2 space-y-1.5 text-sm">
            {FIXPACK_REVIEW.map((item) => (
              <li key={item} className="flex gap-2">
                <span aria-hidden="true" className="text-accent">
                  ✓
                </span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-sm text-muted">
            Linked from the pull request, run against the same code. One review
            per Fix Pack — it is not a subscription.
          </p>

          <p className="mt-4 text-sm text-muted">
            Nothing is merged for you. The pull request sits there until you
            read the diff and decide.
          </p>
        </div>
      </section>

      {/* The two preconditions. Both are real refusals in the API, so a buyer
          who cannot be served should learn it here rather than at checkout. */}
      <section className="mt-6 rounded-xl border border-border bg-surface p-5">
        <h2 className="text-sm font-semibold">Before you can buy a Fix Pack</h2>
        <ul className="mt-2 space-y-1.5 text-sm text-muted">
          <li className="flex gap-2">
            <span aria-hidden="true">1.</span>
            <span>
              Run a free audit on a public GitHub repository. A Fix Pack opens a
              pull request, so there has to be a repository to open it against —
              an uploaded zip cannot be fixed.
            </span>
          </li>
          <li className="flex gap-2">
            <span aria-hidden="true">2.</span>
            <span>
              Install the Drydock GitHub App on that repository, so we can push
              a branch and open the pull request.
            </span>
          </li>
          <li className="flex gap-2">
            <span aria-hidden="true">3.</span>
            <span>
              The audit has to contain something we can actually fix. If it
              doesn&apos;t, checkout refuses rather than selling you a pull
              request with nothing in it.
            </span>
          </li>
        </ul>
      </section>

      {/* Enterprise — not for sale. Dashed and CTA-free on purpose so it reads
          as roadmap, not product. Unchanged from the previous page. */}
      <section className="mt-8 rounded-xl border border-dashed border-border bg-surface/40 p-5">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold text-muted">Enterprise</h2>
          <span className="rounded-full border border-border px-2 py-0.5 text-[10px] uppercase tracking-wide text-muted">
            Coming soon
          </span>
        </div>
        <p className="mt-2 max-w-2xl text-sm text-muted">
          For teams that want Drydock to own more of the path to production.
          These aren&apos;t live yet — no checkout, nothing to buy. Listed here
          so you know where we&apos;re headed.
        </p>
        <ul className="mt-4 grid gap-4 sm:grid-cols-3">
          <li>
            <p className="text-sm font-medium text-text">Preview environments</p>
            <p className="mt-1 text-sm text-muted">
              Spin up a disposable, running copy of a branch to see the fix work
              before it merges.
            </p>
          </li>
          <li>
            <p className="text-sm font-medium text-text">Deploy Pack</p>
            <p className="mt-1 text-sm text-muted">
              Generated Dockerfile and CI workflow so the app is packaged to run
              on your own hosting.
            </p>
          </li>
          <li>
            <p className="text-sm font-medium text-text">
              SBOM &amp; dependency scanning
            </p>
            <p className="mt-1 text-sm text-muted">
              A software bill of materials plus alerts on known vulnerabilities
              in your dependencies.
            </p>
          </li>
        </ul>
      </section>

      <p className="mt-8 text-center text-sm text-muted">
        Already bought something and lost your key?{" "}
        <Link href="/link" className="text-accent underline underline-offset-2">
          Recover it here
        </Link>
        .
      </p>
    </div>
  );
}
