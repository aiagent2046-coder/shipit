"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { FixpackStatus, Pricing } from "@/lib/types";
import {
  createFixpackBankTransferInvoice,
  getFixpackStatus,
  ApiError,
  renewFixpackDeliveryAuthorization,
  getPricing,
} from "@/lib/api";
import { BankTransferCheckout } from "./BankTransferCheckout";
import { CardCheckout } from "./CardCheckout";
import { formatMoney } from "@/lib/format";
import { Spinner } from "./Spinner";
import { SupportEmail } from "./SupportEmail";

const POLL_MS = 10_000;

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
  const [orderStatus, setOrderStatus] = useState<FixpackStatus["status"]>(null);

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
        <FixpackStatusArea key={auditId} auditId={auditId} repoUrl={repoUrl}
          accessToken={accessToken} onStatusChange={setOrderStatus} />
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
        <FixpackStatusArea key={auditId} auditId={auditId} repoUrl={null}
          accessToken={accessToken} onStatusChange={setOrderStatus} />
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

      {!["paid", "running", "awaiting_authorization"].includes(orderStatus ?? "") && (
        <div className="mx-auto mt-5 max-w-md">
          <PaymentMethods
            key={auditId}
            auditId={auditId}
            repoUrl={repoUrl}
            accessToken={accessToken ?? null}
            price={price}
            priceFailed={priceFailed}
          />
        </div>
      )}

      <FixpackStatusArea key={auditId} auditId={auditId} repoUrl={repoUrl} accessToken={accessToken} onStatusChange={setOrderStatus} />
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
  repoUrl,
  accessToken,
  price,
  priceFailed,
}: {
  auditId: string;
  repoUrl: string;
  accessToken: string | null;
  price: Pricing | null;
  /** Distinguishes "still loading" from "we asked and could not find out". */
  priceFailed?: boolean;
}) {
  const [showTransfer, setShowTransfer] = useState(false);
  const [githubToken, setGithubToken] = useState("");

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
      <RepositoryTokenField repoUrl={repoUrl} value={githubToken} onChange={setGithubToken} />
      {card && price && (
        <CardCheckout
          auditId={auditId}
          returnToken={accessToken}
          githubToken={githubToken}
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
          <TransferCheckout auditId={auditId} githubToken={githubToken} />
        </div>
      )}
    </>
  );
}

function TransferCheckout({ auditId, githubToken }: { auditId: string; githubToken: string }) {
  return (
    <BankTransferCheckout
      title="Pay by bank transfer"
      ready={Boolean(githubToken.trim())}
      description={
        <>
          Copy the card number and pay from your banking app. Your Fix Pack
          starts once we&apos;ve seen the money — usually within a business
          day.
        </>
      }
      createInvoice={(payer) =>
        createFixpackBankTransferInvoice(auditId, payer, githubToken.trim())
      }
      renderCompleted={(completed) => completed.product === "fixpack" && completed.funding_review_required ? (
        <p role="alert" className="mt-4 text-sm">
          Payment received. A separate Fix Pack job for this payment has not been confirmed.
          Please contact support with reference {completed.reference} to reconcile the
          payment and determine whether a refund is due. No refund has been issued.
        </p>
      ) : (
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

export function RepositoryTokenField({
  repoUrl, value, onChange, disabled = false,
}: {
  repoUrl: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  return (
    <div className="mb-4 rounded-lg border border-border p-4">
      <p className="text-sm font-semibold">Authorize delivery to your repository</p>
      <p className="mt-2 break-all font-mono text-xs">{repoUrl}</p>
      <p className="mt-2 text-sm text-muted">
        Create a GitHub fine-grained personal access token for this repository only,
        with Contents and Pull requests permissions set to Read and write.
        You must have write access to the repository.
      </p>
      <a href="https://github.com/settings/personal-access-tokens/new"
        target="_blank" rel="noopener noreferrer"
        className="mt-2 inline-block text-sm text-accent underline">
        Create a GitHub token ↗
      </a>
      <label className="mt-3 block text-sm">
        GitHub delivery token
        <input type="password" autoComplete="off" spellCheck={false}
          value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled}
          className="mt-1 w-full rounded-md border border-border bg-surface px-3 py-2"
          maxLength={4096} />
      </label>
      <p className="mt-2 text-xs text-muted">
        This token stays out of browser storage. Drydock stores it encrypted for
        delivery authorization lasting up to 7 days, checks access again before
        opening the PR, and uses only this token to write. GitHub enforces its
        permissions on each write. You can revoke it in GitHub at any time.
      </p>
    </div>
  );
}

function RenewDeliveryAuthorization({
  auditId, accessToken, repoUrl, initialReference, onRenewed,
}: {
  auditId: string;
  accessToken: string;
  repoUrl: string;
  initialReference?: string | null;
  onRenewed: () => void;
}) {
  const [reference, setReference] = useState(initialReference ?? "");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function renew() {
    if (!reference.trim() || !token.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await renewFixpackDeliveryAuthorization(auditId, reference.trim(), accessToken, token.trim());
      setToken("");
      onRenewed();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not renew repository access. Please try again.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="rounded-md border border-high/40 bg-high/10 p-4 text-sm">
      <p className="font-semibold">Renew GitHub access to continue your paid Fix Pack</p>
      <p className="mt-2 text-muted">
        Your order is waiting for repository authorization. Enter your payment
        reference and a fresh token below. This resumes the existing order and
        does not create another payment.
      </p>
      <label className="my-3 block">
        Payment reference
        <input value={reference} onChange={(e) => setReference(e.target.value)}
          autoComplete="off" disabled={busy}
          className="mt-1 w-full rounded-md border border-border bg-surface px-3 py-2" />
      </label>
      <RepositoryTokenField repoUrl={repoUrl} value={token} onChange={setToken} disabled={busy} />
      <button type="button" onClick={renew} disabled={busy || !reference.trim() || !token.trim()}
        className="rounded-lg bg-accent px-4 py-2 font-medium text-accent-fg disabled:opacity-60">
        {busy ? "Checking repository access…" : "Authorize and resume existing order"}
      </button>
      {error && <p role="alert" className="mt-2 text-critical">{error}</p>}
      <p className="mt-2 text-xs text-muted">Missing the payment reference? Email <SupportEmail /> with your order details.</p>
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
 * repository changing between audit and purchase, or a credential being revoked
 * after checkout.
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

function FixpackStatusArea({ auditId, repoUrl, accessToken, onStatusChange }: {
  auditId: string;
  repoUrl: string | null;
  accessToken?: string | null;
  onStatusChange: (status: FixpackStatus["status"]) => void;
}) {
  const [status, setStatus] = useState<FixpackStatus | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stop = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => {
    setStatus(null);
    onStatusChange(null);
    if (!accessToken) return;
    const token = accessToken;
    let cancelled = false;

    async function check() {
      try {
        const s = await getFixpackStatus(auditId, token);
        if (cancelled) return;
        setStatus(s);
        onStatusChange(s.status);
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
  }, [auditId, accessToken, stop, onStatusChange]);

  // Nothing purchased yet — keep the area quiet rather than show an empty box.
  if (!status || status.status === null) return null;

  return (
    <div className="mt-5 border-t border-border pt-5">
      <h3 className="text-sm font-semibold text-muted">Fix Pack status</h3>
      <div className="mt-2">
        {status.status === "awaiting_authorization" && accessToken && (repoUrl ? (
          <RenewDeliveryAuthorization key={status.delivery_reference ?? "missing-reference"}
            auditId={auditId} accessToken={accessToken} repoUrl={repoUrl}
            initialReference={status.delivery_reference}
            onRenewed={() => { setStatus({ ...status, status: "paid" }); onStatusChange("paid"); }} />
        ) : (
          <p className="rounded-md border border-high/40 bg-high/10 p-3 text-sm">
            Your paid order needs repository authorization, but this audit has no
            repository URL. Please <SupportContact /> so we can review the order.
          </p>
        ))}
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
            {status.block_reason === "proof_failed"
              ? "A verification check still detected the reported issue after applying the generated fix, so the pull request was not opened."
              : "The generated fix did not pass verification, so the pull request was not opened."}
            {" "}Your payment was received — <SupportContact /> so we can review
            your order.
            {status.job_id && (
              <span className="mt-2 block break-all">
                Include this support reference: <code>{status.job_id}</code>
              </span>
            )}
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
