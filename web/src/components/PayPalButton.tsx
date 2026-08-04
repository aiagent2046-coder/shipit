"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  PAYPAL_CLIENT_ID,
  ApiError,
  createPaypalOrder,
  createPaypalSubscription,
  getPaypalOrder,
} from "@/lib/api";
import { useApiKey } from "./providers";
import { Spinner } from "./Spinner";
import { SupportEmail } from "./SupportEmail";

// Minimal shape of the parts of the PayPal JS SDK we actually call. Declared
// here (rather than pulling in @paypal/* type packages) because the SDK is
// loaded at runtime by <script>, consistent with the rest of this codebase
// hand-rolling its integrations. Keeps us off `any` under TS strict.
interface PayPalOrderActions {
  order?: { capture: () => Promise<unknown> };
}
interface PayPalButtonsConfig {
  style?: Record<string, string | number>;
  createOrder?: () => Promise<string>;
  createSubscription?: () => Promise<string>;
  onApprove?: (
    data: { orderID?: string; subscriptionID?: string },
    actions: PayPalOrderActions,
  ) => void | Promise<void>;
  onError?: (err: unknown) => void;
  onCancel?: () => void;
}
interface PayPalButtonsInstance {
  render: (container: HTMLElement) => Promise<void>;
  close?: () => void;
}
interface PayPalNamespace {
  Buttons: (config: PayPalButtonsConfig) => PayPalButtonsInstance;
}

// One SDK load per namespace, shared across mounts. Orders and subscriptions
// need DIFFERENT SDK configs (subscriptions require intent=subscription&vault),
// which can't coexist on one global — so each loads under its own
// data-namespace (window.paypalOrders vs window.paypalSubs), the officially
// supported way to run two SDK configs on the same page.
const sdkPromises = new Map<string, Promise<PayPalNamespace>>();

function loadPaypalSdk(
  namespace: string,
  params: Record<string, string>,
): Promise<PayPalNamespace> {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("no window"));
  }
  const globals = window as unknown as Record<string, PayPalNamespace | undefined>;
  if (globals[namespace]) return Promise.resolve(globals[namespace]!);
  const cached = sdkPromises.get(namespace);
  if (cached) return cached;

  const promise = new Promise<PayPalNamespace>((resolve, reject) => {
    const query = new URLSearchParams({
      "client-id": PAYPAL_CLIENT_ID,
      currency: "USD",
      components: "buttons",
      ...params,
    });
    const script = document.createElement("script");
    script.src = `https://www.paypal.com/sdk/js?${query.toString()}`;
    script.setAttribute("data-namespace", namespace);
    script.async = true;
    script.onload = () => {
      const ns = globals[namespace];
      if (ns) resolve(ns);
      else reject(new Error("PayPal SDK loaded but namespace missing"));
    };
    script.onerror = () => reject(new Error("Failed to load PayPal SDK"));
    document.body.appendChild(script);
  });
  sdkPromises.set(namespace, promise);
  return promise;
}

function NotConfigured() {
  return (
    <div className="mt-4 rounded-md border border-high/40 bg-high/10 p-3 text-sm text-high">
      PayPal isn&apos;t configured for this site. Set{" "}
      <code className="font-mono">NEXT_PUBLIC_PAYPAL_CLIENT_ID</code> in the
      frontend&apos;s environment (and the PayPal credentials on the backend) to
      enable this button.
    </div>
  );
}

/**
 * Renders PayPal Buttons for a ONE-TIME order (Pro or a Fix Pack). The button
 * asks our backend to open the order (createPaypalOrder), the buyer approves in
 * the PayPal popup, we capture (actions.order.capture) which fires the
 * PAYMENT.CAPTURE.COMPLETED webhook that grants server-side. For Pro we then
 * poll GET /v1/paypal/orders/{id} to reveal the key; for a Fix Pack there's no
 * key — the audit page's Fix Pack status area shows the generated PR.
 */
export function PayPalOrderCard({
  product,
  auditId,
  title = "Pay with PayPal",
  description,
}: {
  product: "pro" | "fixpack";
  auditId?: string;
  title?: string;
  description: React.ReactNode;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const renderedRef = useRef(false);
  const orderIdRef = useRef<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<"idle" | "approved" | "completed">("idle");
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [alreadyDelivered, setAlreadyDelivered] = useState(false);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const pollForKey = useCallback(
    (orderId: string) => {
      stopPolling();
      pollRef.current = setInterval(async () => {
        try {
          const status = await getPaypalOrder(orderId);
          if (status.status === "completed") {
            stopPolling();
            setPhase("completed");
            setApiKey(status.api_key);
            setAlreadyDelivered(status.key_already_delivered === true);
          }
        } catch {
          /* transient; keep polling */
        }
      }, 4000);
    },
    [stopPolling],
  );

  useEffect(() => () => stopPolling(), [stopPolling]);

  useEffect(() => {
    if (!PAYPAL_CLIENT_ID || renderedRef.current) return;
    renderedRef.current = true;
    let cancelled = false;
    let instance: PayPalButtonsInstance | null = null;

    loadPaypalSdk("paypalOrders", {})
      .then((ns) => {
        if (cancelled || !containerRef.current) return;
        instance = ns.Buttons({
          style: { layout: "horizontal", height: 40 },
          createOrder: async () => {
            setError(null);
            try {
              const order = await createPaypalOrder(product, auditId);
              orderIdRef.current = order.order_id;
              return order.order_id;
            } catch (e) {
              setError(paypalCreateError(e));
              throw e;
            }
          },
          onApprove: async (_data, actions) => {
            setPhase("approved");
            try {
              await actions.order?.capture();
            } catch {
              /* capture may already be handled server-side via webhook */
            }
            if (product === "pro" && orderIdRef.current) {
              pollForKey(orderIdRef.current);
            }
          },
          onError: () => setError("PayPal reported an error. Please try again."),
        });
        instance.render(containerRef.current).catch(() => {
          if (!cancelled) setError("Could not render the PayPal button.");
        });
      })
      .catch(() => {
        if (!cancelled) setError("Could not load PayPal.");
      });

    return () => {
      cancelled = true;
      try {
        instance?.close?.();
      } catch {
        /* ignore */
      }
    };
  }, [product, auditId, pollForKey]);

  return (
    <div className="rounded-xl border border-border bg-elevated p-5">
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="mt-1 text-sm text-muted">{description}</p>

      {!PAYPAL_CLIENT_ID ? (
        <NotConfigured />
      ) : (
        <>
          {phase !== "completed" && (
            <div ref={containerRef} className="mt-4 min-h-[44px]" />
          )}

          {error && (
            <p
              className="mt-3 rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical"
              role="alert"
            >
              {error}
            </p>
          )}

          {phase === "approved" && product === "pro" && (
            <p className="mt-3 flex items-center gap-2 text-sm text-muted">
              <Spinner /> Payment approved — unlocking your Pro key…
            </p>
          )}

          {phase === "approved" && product === "fixpack" && (
            <div className="mt-3 rounded-md border border-accent/40 bg-accent/10 p-4">
              <p className="font-semibold text-accent">
                Payment approved — generating your Fix Pack.
              </p>
              <p className="mt-2 text-sm text-muted">
                No further action needed. The fix PR is opened automatically —
                its status appears below.
              </p>
            </div>
          )}

          {phase === "completed" && product === "pro" && (
            <ProKeyReveal
              apiKey={apiKey}
              alreadyDelivered={alreadyDelivered}
              orderId={orderIdRef.current}
            />
          )}
        </>
      )}
    </div>
  );
}

function ProKeyReveal({
  apiKey,
  alreadyDelivered,
  orderId,
}: {
  apiKey: string | null;
  alreadyDelivered: boolean;
  orderId: string | null;
}) {
  const { setKey } = useApiKey();
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copy() {
    if (!apiKey) return;
    try {
      await navigator.clipboard.writeText(apiKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div className="mt-4 rounded-md border border-accent/40 bg-accent/10 p-4">
      <p className="font-semibold text-accent">
        Payment confirmed — you&apos;re Pro.
      </p>
      {apiKey ? (
        <>
          <p className="mt-2 text-sm text-muted">Your API key:</p>
          <code className="mt-1 block break-all rounded bg-surface p-2 font-mono text-sm">
            {apiKey}
          </code>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={copy}
              className="rounded-md border border-border px-3 py-1.5 text-sm hover:border-accent"
            >
              {copied ? "Copied!" : "Copy key"}
            </button>
            <button
              type="button"
              onClick={async () => {
                await setKey(apiKey);
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
      ) : alreadyDelivered ? (
        <p className="mt-2 text-sm text-muted">
          This key was already delivered once. For security it is shown only
          once and is never stored, so it can&apos;t be shown again — if you
          didn&apos;t save it, email <SupportEmail /> with order id{" "}
          <span className="font-mono">{orderId}</span> to have it reissued.
        </p>
      ) : (
        <p className="mt-2 text-sm text-muted">
          Payment recorded, but the key wasn&apos;t returned yet. Email{" "}
          <SupportEmail /> with order id{" "}
          <span className="font-mono">{orderId}</span>.
        </p>
      )}
    </div>
  );
}

/**
 * Renders PayPal Buttons for the RECURRING monitoring subscription. The button
 * asks our backend to open the subscription (createPaypalSubscription, which
 * pre-inserts the row bound to this repo) and returns its id; the buyer
 * approves, and PayPal delivers the ACTIVATED / SALE webhooks that activate and
 * renew it server-side.
 */
export function PayPalSubscriptionCard({
  repoUrl,
  title = "Subscribe with PayPal",
  description,
}: {
  repoUrl: string;
  title?: string;
  description: React.ReactNode;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const renderedRef = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [approved, setApproved] = useState(false);

  useEffect(() => {
    if (!PAYPAL_CLIENT_ID || renderedRef.current) return;
    renderedRef.current = true;
    let cancelled = false;
    let instance: PayPalButtonsInstance | null = null;

    loadPaypalSdk("paypalSubs", { vault: "true", intent: "subscription" })
      .then((ns) => {
        if (cancelled || !containerRef.current) return;
        instance = ns.Buttons({
          style: { layout: "horizontal", height: 40 },
          createSubscription: async () => {
            setError(null);
            try {
              const sub = await createPaypalSubscription(repoUrl);
              return sub.subscription_id;
            } catch (e) {
              setError(paypalCreateError(e));
              throw e;
            }
          },
          onApprove: () => setApproved(true),
          onError: () => setError("PayPal reported an error. Please try again."),
        });
        instance.render(containerRef.current).catch(() => {
          if (!cancelled) setError("Could not render the PayPal button.");
        });
      })
      .catch(() => {
        if (!cancelled) setError("Could not load PayPal.");
      });

    return () => {
      cancelled = true;
      try {
        instance?.close?.();
      } catch {
        /* ignore */
      }
    };
  }, [repoUrl]);

  return (
    <div className="rounded-xl border border-border bg-elevated p-5">
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="mt-1 text-sm text-muted">{description}</p>

      {!PAYPAL_CLIENT_ID ? (
        <NotConfigured />
      ) : (
        <>
          {!approved && <div ref={containerRef} className="mt-4 min-h-[44px]" />}

          {error && (
            <p
              className="mt-3 rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical"
              role="alert"
            >
              {error}
            </p>
          )}

          {approved && (
            <div className="mt-3 rounded-md border border-accent/40 bg-accent/10 p-4">
              <p className="font-semibold text-accent">
                Subscription approved — monitoring is being enabled.
              </p>
              <p className="mt-2 text-sm text-muted">
                We&apos;ll re-audit this repository on each push to its default
                branch and alert you to new critical or high findings.
              </p>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function paypalCreateError(e: unknown): string {
  if (e instanceof ApiError) {
    if (
      e.reason === "paypal_not_configured" ||
      e.reason === "paypal_plan_not_configured" ||
      e.reason === "not_persisted"
    ) {
      return (
        "PayPal isn't fully configured on the backend yet. Try Telegram Stars " +
        "or USDT, or ask the operator to finish the PayPal setup."
      );
    }
    return e.message;
  }
  return "Could not start the PayPal checkout.";
}
