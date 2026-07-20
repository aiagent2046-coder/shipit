"use client";

import { useState } from "react";
import { TELEGRAM_BOT_USERNAME } from "@/lib/api";

const STARS_PRICE = "600 Stars / 30 days";

// Continuous monitoring re-audits the repo on each push to its default branch
// (at most once per day) and DMs you any NEW critical/high findings. Like the
// Fix Pack Stars flow it's driven by a copy-command to the bot -- the bot sends
// a recurring Stars invoice whose payload binds this audit's repo. Unlike a Fix
// Pack it opens no PR, so there's no GitHub App install gate: a public repo URL
// is all it needs.
export function MonitoringPurchase({
  auditId,
  repoUrl,
}: {
  auditId: string;
  repoUrl: string | null;
}) {
  if (!repoUrl) {
    return (
      <section className="mt-8 rounded-xl border border-border bg-elevated p-5 sm:p-6">
        <h2 className="text-lg font-semibold">Continuous monitoring</h2>
        <p className="mt-2 text-sm text-muted">
          Continuous monitoring requires an audit run from a GitHub URL. Re-run
          this audit with your repo&apos;s GitHub link to enable it — monitoring
          watches a repository for new issues on every push, so there needs to
          be a repo to watch (a zip upload has none).
        </p>
      </section>
    );
  }

  return (
    <section className="mt-8 rounded-xl border border-border bg-elevated p-5 sm:p-6">
      <header>
        <h2 className="text-lg font-semibold">
          Enable continuous monitoring for this repo
        </h2>
        <p className="mt-2 max-w-2xl text-sm text-muted">
          We re-audit the repository on each push to its default branch (at most
          once a day) and send you a Telegram message the moment a{" "}
          <span className="font-medium text-text">new</span> critical or high
          finding appears. A recurring subscription —{" "}
          <span className="font-medium text-text">{STARS_PRICE}</span>, cancel
          anytime with <code className="font-mono">/unsubscribe</code>.
        </p>
      </header>

      <MonitorStarsCard auditId={auditId} />
    </section>
  );
}

function MonitorStarsCard({ auditId }: { auditId: string }) {
  const [copied, setCopied] = useState(false);
  const command = `/monitor ${auditId}`;
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
    <div className="mt-5 rounded-xl border border-border bg-elevated p-5">
      <h3 className="text-lg font-semibold">Start with Telegram Stars</h3>
      <p className="mt-1 text-sm text-muted">
        Open the bot and send the command below. It starts a recurring Stars
        subscription and binds monitoring to this audit&apos;s repository.
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
