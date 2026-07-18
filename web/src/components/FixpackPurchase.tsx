"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { FixpackStatus } from "@/lib/types";
import {
  TELEGRAM_BOT_USERNAME,
  createFixpackUsdtInvoice,
  getFixpackStatus,
} from "@/lib/api";
import { UsdtCheckout } from "./UsdtCheckout";
import { Spinner } from "./Spinner";

const STARS_PRICE = "600 Stars";
const USDT_PRICE = "12 USDT";
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

      <div className="mt-5 grid gap-5 md:grid-cols-2">
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
      </div>

      <FixpackStatusArea auditId={auditId} />
    </section>
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
        {status.status === "paid" && (
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

        {status.status === "failed" && (
          <p className="rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical">
            Fix Pack generation failed. Your payment was received but the fix PR
            couldn&apos;t be opened — contact the operator to sort it out.
          </p>
        )}
      </div>
    </div>
  );
}
