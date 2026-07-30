"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { FixpackStatus, InstallationStatus } from "@/lib/types";
import {
  TELEGRAM_BOT_USERNAME,
  createFixpackBankTransferInvoice,
  createFixpackUsdtInvoice,
  getFixpackStatus,
  getInstallationStatus,
} from "@/lib/api";
import { BankTransferCheckout } from "./BankTransferCheckout";
import { UsdtCheckout } from "./UsdtCheckout";
import { PayPalOrderCard } from "./PayPalButton";
import { Spinner } from "./Spinner";

const STARS_PRICE = "600 Stars";
const USDT_PRICE = "12 USDT";
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
}: {
  auditId: string;
  repoUrl: string | null;
}) {
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
          request against your repository automatically. Pay once —{" "}
          <span className="font-medium text-text">{STARS_PRICE}</span> or{" "}
          <span className="font-medium text-text">{USDT_PRICE}</span>.
        </p>
      </header>

      <InstallGate repoUrl={repoUrl}>
        <div className="mt-5 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          <StarsCard auditId={auditId} />
          <UsdtCheckout
            description={
              <>
                Send an exact amount on the TRON network. Once the transfer is
                confirmed on-chain your Fix Pack is generated automatically —
                watch the status below.
              </>
            }
            createInvoice={() => createFixpackUsdtInvoice(auditId)}
            renderCompleted={() => (
              <div className="mt-4 rounded-md border border-accent/40 bg-accent/10 p-4">
                <p className="font-semibold text-accent">
                  Payment confirmed — generating your Fix Pack.
                </p>
                <p className="mt-2 text-sm text-muted">
                  No further action needed. The fix PR is opened automatically —
                  its status appears below.
                </p>
              </div>
            )}
          />
          <PayPalOrderCard
            product="fixpack"
            auditId={auditId}
            description={
              <>
                Pay once with PayPal (card or balance). Your Fix Pack is
                generated automatically once the payment is captured — watch the
                status below.
              </>
            }
          />
          <BankTransferCheckout
            description={
              <>
                Send a normal bank transfer quoting the reference code below.
                Your Fix Pack starts once we&apos;ve seen the money — usually
                1–3 business days.
              </>
            }
            createInvoice={() => createFixpackBankTransferInvoice(auditId)}
            renderCompleted={() => (
              <div className="mt-4 rounded-md border border-accent/40 bg-accent/10 p-4">
                <p className="font-semibold text-accent">
                  Transfer confirmed — generating your Fix Pack.
                </p>
                <p className="mt-2 text-sm text-muted">
                  No further action needed. The fix PR is opened automatically —
                  its status appears below.
                </p>
              </div>
            )}
          />
        </div>
      </InstallGate>

      <FixpackStatusArea auditId={auditId} />
    </section>
  );
}

// A Fix Pack opens a real PR, which needs the GitHub App installed on the
// target repo. Until it is, we show an "Install GitHub App" button instead of
// the pay cards, so no one pays for a Fix Pack that can't be delivered. When
// the App isn't configured on this deployment at all (app_configured=false),
// or the check can't complete, we don't strand the user — the pay cards show.
function InstallGate({
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

function StarsCard({ auditId }: { auditId: string }) {
  const [copied, setCopied] = useState(false);
  const command = `/fixpack ${auditId}`;
  const telegramConfigured = TELEGRAM_BOT_USERNAME.length > 0;

  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div className="rounded-xl border border-border bg-elevated p-5">
      <h3 className="text-lg font-semibold">Pay with Telegram Stars</h3>
      <p className="mt-1 text-sm text-muted">
        Open the bot and send the command below to pay {STARS_PRICE} and start
        your Fix Pack for this audit.
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
          The Telegram bot username isn&apos;t configured for this site. Set{" "}
          <code className="font-mono">NEXT_PUBLIC_TELEGRAM_BOT_USERNAME</code>{" "}
          in the frontend&apos;s environment to enable this button.
        </div>
      )}

      <div className="mt-4">
        <span className="text-xs text-muted">Then send this command:</span>
        <div className="mt-1 flex items-center justify-between gap-3 rounded-md border border-border bg-surface px-3 py-2 text-sm">
          <code className="break-all font-mono">{command}</code>
          <button
            type="button"
            onClick={copy}
            className="shrink-0 rounded border border-border px-2 py-0.5 text-xs text-muted hover:text-text"
          >
            {copied ? "✓" : "Copy"}
          </button>
        </div>
      </div>
    </div>
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
            Your payment was received — please contact the operator and we&apos;ll
            sort it out.
          </p>
        )}

        {status.status === "failed" &&
          (status.failure_kind === "infrastructure" ? (
            <p className="rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical">
              We couldn&apos;t run the fix on our side — our build environment
              was unavailable, so nothing was checked against your repository.
              This is on us, not your code. Your payment was received — contact
              the operator and we&apos;ll re-run it.
            </p>
          ) : (
            <p className="rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical">
              Fix Pack generation failed. Your payment was received but the fix
              PR couldn&apos;t be opened — contact the operator to sort it out.
            </p>
          ))}
      </div>
    </div>
  );
}
