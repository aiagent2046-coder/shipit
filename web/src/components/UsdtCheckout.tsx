"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { UsdtInvoice, UsdtInvoiceStatus } from "@/lib/types";
import { createUsdtInvoice, getUsdtInvoice, ApiError } from "@/lib/api";
import { useApiKey } from "./providers";
import { Spinner } from "./Spinner";

function useCountdown(expiresAt: string | null): number | null {
  const [remaining, setRemaining] = useState<number | null>(null);
  useEffect(() => {
    if (!expiresAt) {
      setRemaining(null);
      return;
    }
    const end = new Date(expiresAt).getTime();
    const tick = () =>
      setRemaining(Math.max(0, Math.floor((end - Date.now()) / 1000)));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [expiresAt]);
  return remaining;
}

function fmt(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export function UsdtCheckout() {
  const { setKey } = useApiKey();
  const [invoice, setInvoice] = useState<UsdtInvoice | null>(null);
  const [status, setStatus] = useState<UsdtInvoiceStatus | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const remaining = useCountdown(
    invoice && status?.status !== "completed" ? invoice.expires_at : null,
  );

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => () => stopPolling(), [stopPolling]);

  async function start() {
    setCreating(true);
    setError(null);
    setStatus(null);
    try {
      const inv = await createUsdtInvoice();
      setInvoice(inv);
      poll(inv.invoice_id);
    } catch (e) {
      setError(
        e instanceof ApiError
          ? e.reason === "usdt_not_configured" || e.reason === "not_persisted"
            ? "USDT payments aren't configured on the backend yet (USDT_TRC20_ADDRESS / DATABASE_URL). Try Telegram Stars, or ask the operator to configure it."
            : e.message
          : "Could not create a USDT invoice.",
      );
    } finally {
      setCreating(false);
    }
  }

  function poll(invoiceId: string) {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const s = await getUsdtInvoice(invoiceId);
        setStatus(s);
        if (s.status === "completed" || s.status === "expired") {
          stopPolling();
        }
      } catch {
        /* transient; keep polling */
      }
    }, 8000);
  }

  async function copy(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  const completed = status?.status === "completed" ? status : null;
  const expired = status?.status === "expired";

  return (
    <div className="rounded-xl border border-border bg-elevated p-5">
      <h3 className="text-lg font-semibold">Pay with USDT (TRC20)</h3>
      <p className="mt-1 text-sm text-muted">
        Send an exact amount on the TRON network. Your API key unlocks
        automatically once the transfer is confirmed on-chain.
      </p>

      {!invoice && (
        <button
          type="button"
          onClick={start}
          disabled={creating}
          className="mt-4 flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 font-medium text-accent-fg hover:opacity-90 disabled:opacity-60"
        >
          {creating ? (
            <>
              <Spinner /> Creating invoice…
            </>
          ) : (
            "Generate payment address"
          )}
        </button>
      )}

      {error && (
        <p className="mt-4 rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical" role="alert">
          {error}
        </p>
      )}

      {invoice && !completed && !expired && (
        <div className="mt-4 space-y-3">
          <Field
            label="Network"
            value={invoice.network}
            mono
          />
          <Field
            label="Amount (exact)"
            value={`${invoice.amount} ${invoice.currency}`}
            mono
            onCopy={() => copy(String(invoice.amount), "amount")}
            copied={copied === "amount"}
          />
          <Field
            label="Send to address"
            value={invoice.address}
            mono
            breakAll
            onCopy={() => copy(invoice.address, "address")}
            copied={copied === "address"}
          />
          <div className="flex items-center justify-between rounded-md border border-border bg-surface px-3 py-2 text-sm">
            <span className="text-muted">Expires in</span>
            <span className="font-mono tabular-nums">
              {remaining != null ? fmt(remaining) : "—"}
            </span>
          </div>
          <p className="flex items-center gap-2 text-sm text-muted">
            <Spinner /> Waiting for payment… send the{" "}
            <strong>exact</strong> amount so it can be matched.
          </p>
          <p className="text-xs text-muted">
            Send the precise amount shown — matching is on the exact value, and
            a different amount won&apos;t be credited automatically.
          </p>
        </div>
      )}

      {expired && (
        <div className="mt-4 rounded-md border border-high/40 bg-high/10 p-3 text-sm">
          <p className="text-high">This invoice expired before a payment was seen.</p>
          <button
            type="button"
            onClick={start}
            className="mt-2 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg"
          >
            Start over
          </button>
        </div>
      )}

      {completed && (
        <div className="mt-4 rounded-md border border-accent/40 bg-accent/10 p-4">
          <p className="font-semibold text-accent">Payment confirmed — you&apos;re Pro.</p>
          {completed.api_key ? (
            <>
              <p className="mt-2 text-sm text-muted">Your API key:</p>
              <code className="mt-1 block break-all rounded bg-surface p-2 font-mono text-sm">
                {completed.api_key}
              </code>
              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => copy(completed.api_key!, "key")}
                  className="rounded-md border border-border px-3 py-1.5 text-sm hover:border-accent"
                >
                  {copied === "key" ? "Copied!" : "Copy key"}
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    await setKey(completed.api_key!);
                    setSaved(true);
                  }}
                  className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg"
                >
                  {saved ? "Saved to this browser" : "Use this key now"}
                </button>
              </div>
              <p className="mt-2 text-xs text-muted">
                Keep it secret — anyone with it has your pro access.
              </p>
            </>
          ) : (
            <p className="mt-2 text-sm text-muted">
              Payment recorded, but the key wasn&apos;t returned. Contact the
              operator with invoice id{" "}
              <span className="font-mono">{completed.invoice_id}</span>.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function Field({
  label,
  value,
  mono,
  breakAll,
  onCopy,
  copied,
}: {
  label: string;
  value: string;
  mono?: boolean;
  breakAll?: boolean;
  onCopy?: () => void;
  copied?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-border bg-surface px-3 py-2 text-sm">
      <span className="shrink-0 text-muted">{label}</span>
      <span
        className={`text-right ${mono ? "font-mono" : ""} ${
          breakAll ? "break-all" : ""
        }`}
      >
        {value}
      </span>
      {onCopy && (
        <button
          type="button"
          onClick={onCopy}
          className="shrink-0 rounded border border-border px-2 py-0.5 text-xs text-muted hover:text-text"
        >
          {copied ? "✓" : "Copy"}
        </button>
      )}
    </div>
  );
}
