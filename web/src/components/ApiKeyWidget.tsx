"use client";

import { useEffect, useRef, useState } from "react";
import { useApiKey } from "./providers";
import { Spinner } from "./Spinner";

export function ApiKeyWidget() {
  const { account, loading, error, setKey, clearKey } = useApiKey();
  // The key itself is no longer readable from here -- it is in an HttpOnly
  // cookie. Whether a session exists is what this widget ever needed.
  const hasSession = account?.authenticated ?? false;
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState("");
  const popRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (popRef.current && !popRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  const isPro = account?.tier === "pro" && account.authenticated;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!draft.trim()) return;
    await setKey(draft);
    setDraft("");
  }

  return (
    <div className="relative" ref={popRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="dialog"
        className="flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm text-muted transition-colors hover:text-text"
      >
        {loading ? (
          <Spinner />
        ) : (
          <span
            className={`h-2 w-2 rounded-full ${
              isPro ? "bg-accent" : "bg-low"
            }`}
            aria-hidden="true"
          />
        )}
        <span className="hidden sm:inline">
          {isPro ? "Pro" : hasSession ? "Free" : "I have a key"}
        </span>
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="API key"
          className="absolute right-0 z-20 mt-2 w-80 rounded-lg border border-border bg-elevated p-4 shadow-xl"
        >
          <p className="mb-1 text-sm font-medium">Your API key</p>
          <p className="mb-3 text-xs text-muted">
            Paste your <code className="font-mono">sk_live_…</code> key to use
            pro entitlements. Stored in this browser only.
          </p>

          {account && (
            <div className="mb-3 rounded-md border border-border bg-surface px-3 py-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-muted">Tier</span>
                <span className="font-mono font-semibold">
                  {account.tier}
                  {account.authenticated ? "" : " (not recognized)"}
                </span>
              </div>
              <div className="mt-1 flex items-center justify-between">
                <span className="text-muted">Daily audit limit</span>
                <span className="font-mono">
                  {account.entitlements.daily_audit_limit}
                </span>
              </div>
            </div>
          )}

          {error && (
            <p className="mb-2 text-xs text-critical" role="alert">
              {error}
            </p>
          )}

          <form onSubmit={submit} className="flex flex-col gap-2">
            <input
              type="password"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="sk_live_…"
              autoComplete="off"
              spellCheck={false}
              className="w-full rounded-md border border-border bg-surface px-3 py-2 font-mono text-sm outline-hidden focus:border-accent"
            />
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={loading || !draft.trim()}
                className="flex-1 rounded-md bg-accent px-3 py-2 text-sm font-medium text-accent-fg transition-opacity hover:opacity-90 disabled:opacity-50"
              >
                Save key
              </button>
              {hasSession && (
                <button
                  type="button"
                  onClick={() => {
                    clearKey();
                    setOpen(false);
                  }}
                  className="rounded-md border border-border px-3 py-2 text-sm text-muted hover:text-text"
                >
                  Remove
                </button>
              )}
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
