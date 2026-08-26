"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { FixpackStatus, InstallationStatus, Pricing } from "@/lib/types";
import {
  createFixpackBankTransferInvoice,
  getFixpackStatus,
  getInstallationStatus,
  getPricing,
} from "@/lib/api";
import { BankTransferCheckout } from "./BankTransferCheckout";
import { CardCheckout } from "./CardCheckout";
import { formatMoney } from "@/lib/format";
import { Spinner } from "./Spinner";
import { SupportEmail } from "./SupportEmail";

const POLL_MS = 10_000;

// Survives the round trip to github.com and back to /github/installed, so the
// receiver page can send the user straight back to this audit. sessionStorage
// (not query state) because it's same-tab and we don't want it in a URL.
const INSTALL_RETURN_KEY = "drydock:github-install-return";

// Pull owner/repo out of a github.com URL for the installation check. The
// backend re-validates both segments, so this is only about extracting them.
function parseOwnerRepo(
  repoUrl: string,
): { owner: string; repo: string } | null {
  const m = repoUrl
    .trim()
    .match(/^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

const TERMINAL: ReadonlySet<string> = new Set([
  "delivered",
  "no_fix_needed",
  "blocked",
  "failed",
]);

export function FixpackPurchase({
  auditId,
  repoUrl,
  autoFixable,
  accessToken,
}: {
  auditId: string;
  repoUrl: string | null;
  /**
   * The audit's access token, read off this page's own URL. Passed through to
   * the card checkout so ЮKassa can send the buyer back to a page they can
   * read -- `/audit/{id}` without it renders "No audit found for this link".
   */
  accessToken?: string | null;
  /**
   * Whether a Fix Pack could produce anything for this audit, decided by the
   * API (`fixpack_auto_fixable`). Not recomputed here: the answer depends on
   * which rules the Fix Pack knows how to rewrite, and a second copy of that
   * list in TypeScript would drift from the Python one.
   *
   * `undefined` means an older API that doesn't send the field. Treated as
   * "offer it", because the sell endpoints refuse with 409 anyway -- hiding a
   * button was never the protection.
   */
  autoFixable?: boolean;
}) {
  // Fetched, never hardcoded, for the same reason /pricing fetches it: a
  // figure typed into this file is how a page starts contradicting what
  // checkout charges, which is the bait-price shape a stranger walks away
  // from. This block used to promise "the price is shown below" and then show
  // nothing until a name and an email had been handed over.
  const [price, setPrice] = useState<Pricing | null>(null);
  const [priceFailed, setPriceFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getPricing()
      .then((p) => {
        if (!cancelled) setPrice(p);
      })
      .catch(() => {
        if (!cancelled) setPriceFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (repoUrl && autoFixable === false) {
    // Nothing here can be fixed automatically, and that was knowable before
    // anyone paid. Audit 05fa18f5 was sold a Fix Pack in exactly this state:
    // the job ran, found nothing, and the payer was charged for "Nothing to
    // auto-fix". Explain instead of selling.
    return (
      <section className="mt-8 rounded-xl border border-border bg-elevated p-5 sm:p-6">
        <h2 className="text-lg font-semibold">Fix Pack</h2>
        <p className="mt-2 max-w-2xl text-sm text-muted">
          Nothing in this audit can be fixed automatically, so there&apos;s
          nothing to buy. A Fix Pack rewrites hardcoded secrets and a few
          config problems into a pull request; the findings here are
          recommendations, or they live in comments, docs or tests, where
          rewriting them would change nothing an attacker could use.
        </p>
        <p className="mt-2 max-w-2xl text-sm text-muted">
          Work through the recommendations above instead. If you change the
          code and re-run the audit, this section will offer a Fix Pack when
          there&apos;s something for it to do.
        </p>
      </section>
    );
  }

  if (!repoUrl) {
    return (
      <section className="mt-8 rounded-xl border border-border bg-elevated p-5 sm:p-6">
        <h2 className="text-lg font-semibold">Fix Pack</h2>
        <p className="mt-2 text-sm text-muted">
          Fix Pack requires an audit run from a GitHub URL. Re-run this audit
          with your repo&apos;s GitHub link to unlock Fix Pack — a Fix Pack
          opens a real pull request against your repository, so there needs to
          be a repo to open it against (a zip upload has none).
        </p>
      </section>
    );
  }

  return (
    <section className="mt-8 rounded-xl border border-border bg-elevated p-5 sm:p-6">
      <header>
        <h2 className="text-lg font-semibold">
          Get a Fix Pack for this audit
        </h2>
        <p className="mt-2 max-w-2xl text-sm text-muted">
          A Fix Pack generates real fixes for the issues above and opens a pull
          request against your repository automatically, and includes one
          full-depth review of the same code. Paid once by card — not a
          subscription, and nothing recurs.
        </p>
        {/* The price, up front. This block used to promise "the price is shown
            below" and then show nothing until the buyer had handed over a name
            and an email to generate an invoice. Fetched from /v1/pricing so it
            cannot drift from what checkout charges. */}
        <p className="mt-3 text-sm" aria-live="polite">
          {price ? (
            <>
              <span className="font-mono text-2xl font-semibold">
                {formatMoney(price.fixpack.amount, price.fixpack.currency)}
              </span>
              <span className="ml-2 text-muted">per audit</span>
            </>
          ) : priceFailed ? (
            <span className="text-muted">
              We couldn&apos;t load the current price. Email{" "}
              <SupportEmail /> and we&apos;ll confirm it before you pay
              anything.
            </span>
          ) : (
            <span className="text-muted">Loading the price…</span>
          )}
        </p>
      </header>

      <InstallGate repoUrl={repoUrl}>
        <div className="mx-auto mt-5 max-w-md">
          <PaymentMethods
            auditId={auditId}
            accessToken={accessToken ?? null}
            price={price}
            priceFailed={priceFailed}
          />
        </div>
      </InstallGate>

      <FixpackStatusArea auditId={auditId} />
    </section>
  );
}

/**
 * Which ways to pay this deployment actually has, and in which order.
 *
 * THE ORDER IS THE PRODUCT DECISION. A card through ЮKassa finishes in
 * seconds; the manual transfer needs a person to read a bank statement, which
 * is measured in hours. Offering them side by side would let a buyer pick the
 * slow one without knowing it is the slow one, so the card is the visible
 * checkout and the transfer is a disclosure underneath it.
 *
 * THE TRANSFER IS NOT DELETED, and that is not sentiment. It is the fallback
 * for a card that a Russian bank declines, and it is what this deployment ran
 * on for its whole life before ЮKassa; deleting it the day the new rail
 * shipped would put every such buyer at a dead end.
 *
 * WHAT IS LIVE COMES FROM THE API. `methods` is read from /v1/pricing rather
 * than assumed, because the alternative is rendering a button, taking a click
 * and answering 503 -- which reads to a buyer as "this is broken", not as "pay
 * the other way". An older API sends no `methods` at all, which is read as the
 * state every deployment was in before this rail existed: transfer only.
 */
export function PaymentMethods({
  auditId,
  accessToken,
  price,
  priceFailed,
}: {
  auditId: string;
  accessToken: string | null;
  price: Pricing | null;
  /** Distinguishes "still loading" from "we asked and could not find out". */
  priceFailed?: boolean;
}) {
  const [showTransfer, setShowTransfer] = useState(false);

  // Nothing at all while the answer is still in flight. Which rails exist is
  // part of that answer, so rendering a checkout first means rendering a
  // GUESS — and a guess visibly swapping under someone who has started typing
  // into it is worse than a moment of nothing.
  if (!price && !priceFailed) return null;

  // A price we could not load is a card rail we cannot offer: the checkout has
  // to name the figure it is about to charge, and a pay button naming no
  // figure is the bait-price shape this section was rewritten to remove. That
  // falls out rather than being enforced -- `methods` arrives in the same
  // response as the amount, so no price means no methods either, and the two
  // cannot disagree. An explicit `&& price !== null` here would read as a
  // guard while being unreachable.
  const methods = price?.methods;
  const card = methods?.card ?? false;
  const transfer = methods?.bank_transfer ?? true;

  if (!card && !transfer) {
    return (
      <p className="text-sm text-muted">
        Card payment is being set up on this deployment. Email{" "}
        <SupportEmail /> and we&apos;ll take payment another way and start your
        Fix Pack by hand.
      </p>
    );
  }

  return (
    <>
      {card && price && (
        <CardCheckout
          auditId={auditId}
          returnToken={accessToken}
          amount={price.fixpack.amount}
          currency={price.fixpack.currency}
        />
      )}

      {card && transfer && !showTransfer && (
        <button
          type="button"
          onClick={() => setShowTransfer(true)}
          className="mt-3 w-full text-center text-sm text-muted underline underline-offset-2 hover:text-text"
        >
          Card declined? Pay by bank transfer instead
        </button>
      )}

      {transfer && (!card || showTransfer) && (
        <div className={card ? "mt-4" : undefined}>
          <TransferCheckout auditId={auditId} />
        </div>
      )}
    </>
  );
}

function TransferCheckout({ auditId }: { auditId: string }) {
  return (
    <BankTransferCheckout
      title="Pay by bank transfer"
      description={
        <>
          Copy the card number and pay from your banking app. Your Fix Pack
          starts once we&apos;ve seen the money — usually within a business
          day.
        </>
      }
      createInvoice={(payer) =>
        createFixpackBankTransferInvoice(auditId, payer)
      }
      renderCompleted={() => (
        <div className="mt-4 rounded-md border border-accent/40 bg-accent/10 p-4">
          <p className="font-semibold text-accent">
            Transfer confirmed — generating your Fix Pack.
          </p>
          <p className="mt-2 text-sm text-muted">
            No further action needed. The fix PR is opened automatically — its
            status appears below.
          </p>
        </div>
      )}
    />
  );
}

// A Fix Pack opens a real PR, which needs the GitHub App installed on the
// target repo. Until it is, we show an "Install GitHub App" button instead of
// the pay cards, so no one pays for a Fix Pack that can't be delivered. When
// the App isn't configured on this deployment at all (app_configured=false),
// or the check can't complete, we don't strand the user — the pay cards show.
export function InstallGate({
  repoUrl,
  children,
}: {
  repoUrl: string;
  children: ReactNode;
}) {
  const [status, setStatus] = useState<InstallationStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  const parsed = parseOwnerRepo(repoUrl);

  useEffect(() => {
    if (!parsed) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setFailed(false);
    getInstallationStatus(parsed.owner, parsed.repo)
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // parsed is derived from repoUrl; keying on repoUrl avoids a new object
    // each render retriggering the effect.
  }, [repoUrl]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) {
    return (
      <p className="mt-5 flex items-center gap-2 text-sm text-muted">
        <Spinner /> Checking GitHub App installation…
      </p>
    );
  }

  // Couldn't parse the repo, the App isn't configured here, it's already
  // installed, or the check failed — in every one of these the honest move is
  // to let the purchase proceed rather than block on an unknown.
  const blocked =
    status !== null &&
    status.app_configured &&
    status.installed === false &&
    !failed;

  if (!blocked) return <>{children}</>;

  function rememberReturn() {
    try {
      sessionStorage.setItem(INSTALL_RETURN_KEY, window.location.href);
    } catch {
      /* sessionStorage unavailable — /github/installed falls back to home */
    }
  }

  // Installed AND suspended is a different problem with a different fix, and
  // telling this person to "install the GitHub App" would be telling them to
  // do something they have already done. The purchase is blocked either way;
  // only the sentence changes.
  if (status!.suspended) {
    return (
      <div className="mt-5 rounded-xl border border-high/40 bg-high/10 p-5">
        <h3 className="text-base font-semibold text-high">
          The GitHub App is suspended on this repository
        </h3>
        <p className="mt-2 max-w-2xl text-sm text-muted">
          Our GitHub App is installed on{" "}
          <span className="font-mono text-text">
            {status!.owner}/{status!.repo}
          </span>{" "}
          but suspended, so it cannot open a pull request — and a Fix Pack is
          delivered as one. Whoever owns the repository can lift it under
          Settings → Applications → Installed GitHub Apps → Configure, then
          reload this page.
        </p>
      </div>
    );
  }

  return (
    <div className="mt-5 rounded-xl border border-high/40 bg-high/10 p-5">
      <h3 className="text-base font-semibold text-high">
        Install the GitHub App first
      </h3>
      <p className="mt-2 max-w-2xl text-sm text-muted">
        A Fix Pack opens a real pull request against{" "}
        <span className="font-mono text-text">
          {status!.owner}/{status!.repo}
        </span>
        , so our GitHub App has to be installed on that repository before you
        can buy one. Install it (you choose which repos it can access), and
        you&apos;ll be brought right back here to continue.
      </p>
      {status!.install_url && (
        <a
          href={status!.install_url}
          rel="noreferrer"
          onClick={rememberReturn}
          className="mt-4 inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 font-medium text-accent-fg hover:opacity-90"
        >
          Install GitHub App ↗
        </a>
      )}
    </div>
  );
}

/**
 * The way out of a paid order that did not deliver.
 *
 * These three branches used to say "contact the operator" with no address
 * anywhere in this file. That is the branch which decides whether a failed
 * sale becomes a refund conversation or an accusation of fraud, and it is
 * reachable through no fault of the buyer: the sandbox runner being down, the
 * repository changing between audit and purchase, or the App being uninstalled
 * after the install gate above passed.
 *
 * Names what to include, because the operator matches an incoming transfer on
 * the order number where the bank carried one and on the payer's name and
 * amount where it did not.
 */
function SupportContact() {
  return (
    <>
      email <SupportEmail /> with the name you paid under and the exact amount
    </>
  );
}

function FixpackStatusArea({ auditId }: { auditId: string }) {
  const [status, setStatus] = useState<FixpackStatus | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stop = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const s = await getFixpackStatus(auditId);
        if (cancelled) return;
        setStatus(s);
        if (s.status && TERMINAL.has(s.status)) stop();
      } catch {
        /* transient; keep polling */
      }
    }

    void check();
    pollRef.current = setInterval(check, POLL_MS);
    return () => {
      cancelled = true;
      stop();
    };
  }, [auditId, stop]);

  // Nothing purchased yet — keep the area quiet rather than show an empty box.
  if (!status || status.status === null) return null;

  return (
    <div className="mt-5 border-t border-border pt-5">
      <h3 className="text-sm font-semibold text-muted">Fix Pack status</h3>
      <div className="mt-2">
        {(status.status === "paid" || status.status === "running") && (
          <p className="flex items-center gap-2 text-sm text-muted">
            <Spinner /> Generating your fix… this opens a pull request
            automatically and can take a couple of minutes.
          </p>
        )}

        {status.status === "delivered" && (
          <div className="rounded-md border border-accent/40 bg-accent/10 p-3 text-sm">
            <p className="font-semibold text-accent">Your fix PR is open.</p>
            {status.pr_url ? (
              <a
                href={status.pr_url}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-1 inline-block break-all text-accent hover:underline"
              >
                PR opened: {status.pr_url} ↗
              </a>
            ) : (
              <p className="mt-1 text-muted">
                The PR was opened — check your repository&apos;s pull requests.
              </p>
            )}
          </div>
        )}

        {status.status === "no_fix_needed" && (
          <p className="rounded-md border border-border bg-surface p-3 text-sm text-muted">
            Nothing to auto-fix — see the recommendations above.
          </p>
        )}

        {status.status === "blocked" && (
          <p className="rounded-md border border-high/40 bg-high/10 p-3 text-sm text-high">
            An automated check found a potential problem in the generated fix
            (it made the repository&apos;s tests worse), so the pull request was
            not opened and the change is held for manual review by our team.
            Your payment was received — <SupportContact /> and we&apos;ll sort it
            out.
          </p>
        )}

        {status.status === "failed" &&
          (status.failure_kind === "infrastructure" ? (
            <p className="rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical">
              We couldn&apos;t run the fix on our side — our build environment
              was unavailable, so nothing was checked against your repository.
              This is on us, not your code. Your payment was received —{" "}
              <SupportContact /> and we&apos;ll re-run it.
            </p>
          ) : (
            <p className="rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical">
              Fix Pack generation failed. Your payment was received but the fix
              PR couldn&apos;t be opened — <SupportContact /> and we&apos;ll sort
              it out.
            </p>
          ))}
      </div>
    </div>
  );
}
