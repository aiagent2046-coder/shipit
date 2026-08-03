// Thin fetch client for the Drydock FastAPI backend. No backend of our
// own — every call here is a cross-origin request to NEXT_PUBLIC_API_BASE_URL.

import type {
  Account,
  AuditJobStatus,
  AuditResult,
  BankTransferInvoice,
  BankTransferPaidResult,
  BankTransferStatus,
  BillingDetails,
  CreateAuditResponse,
  FixpackStatus,
  FixpackUsdtInvoice,
  InstallationStatus,
  PaypalOrder,
  PaypalOrderStatus,
  PaypalSubscription,
  PersistedAudit,
  UsdtInvoice,
  UsdtInvoiceStatus,
} from "./types";

export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000"
).replace(/\/+$/, "");

export const TELEGRAM_BOT_USERNAME =
  process.env.NEXT_PUBLIC_TELEGRAM_BOT_USERNAME || "";

// PayPal JS SDK client id (public, client-side). Empty -> the PayPal buttons
// render as an "unconfigured" note rather than loading the SDK, mirroring the
// Telegram-username guard. The matching secret lives ONLY on the backend.
export const PAYPAL_CLIENT_ID = process.env.NEXT_PUBLIC_PAYPAL_CLIENT_ID || "";

// A typed error carrying the backend's {reason, detail} envelope when present,
// so the UI can show something honest instead of "something went wrong".
export class ApiError extends Error {
  status: number;
  reason?: string;
  constructor(message: string, status: number, reason?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.reason = reason;
  }
}

function authHeaders(apiKey?: string | null): Record<string, string> {
  return apiKey ? { Authorization: `Bearer ${apiKey}` } : {};
}

async function parse<T>(res: Response): Promise<T> {
  const text = await res.text();
  let body: unknown = undefined;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  if (!res.ok) {
    // FastAPI puts the error under `detail`, which in this codebase is
    // usually {reason, detail}. Surface both cleanly.
    const detail = (body as { detail?: unknown } | undefined)?.detail;
    let message = `Request failed (${res.status})`;
    let reason: string | undefined;
    if (detail && typeof detail === "object") {
      const d = detail as { reason?: string; detail?: string };
      reason = d.reason;
      message = d.detail || d.reason || message;
    } else if (typeof detail === "string") {
      message = detail;
    }
    throw new ApiError(message, res.status, reason);
  }
  return body as T;
}

// Wrap network-level failures (backend down, DNS, CORS block) so callers
// always get an ApiError with a human message rather than a raw TypeError.
async function request(input: string, init?: RequestInit): Promise<Response> {
  try {
    return await fetch(input, init);
  } catch (e) {
    throw new ApiError(
      `Could not reach the backend at ${API_BASE_URL}. It may be down, or ` +
        `this site's origin may not be allowed by the backend's CORS config.`,
      0,
      "network_error",
    );
  }
}

export async function getAccount(apiKey?: string | null): Promise<Account> {
  const res = await request(`${API_BASE_URL}/v1/account`, {
    headers: { ...authHeaders(apiKey) },
  });
  return parse<Account>(res);
}

// Submits an audit. The scan itself runs in the backend's audit worker, so the
// normal answer is an AuditJobAccepted to poll with getAuditJob; the exception
// is a content-cache hit, which comes back as a finished AuditResult. Use
// isAuditJobAccepted to tell them apart.
export async function createAudit(
  input: { repoUrl?: string; file?: File },
  apiKey?: string | null,
): Promise<CreateAuditResponse> {
  const form = new FormData();
  if (input.file) {
    form.append("archive", input.file);
  } else if (input.repoUrl) {
    form.append("repo_url", input.repoUrl);
  }
  const res = await request(`${API_BASE_URL}/v1/audits`, {
    method: "POST",
    headers: { ...authHeaders(apiKey) },
    body: form,
  });
  return parse<CreateAuditResponse>(res);
}

// Poll one queued audit. Gated by the JOB's access token (from createAudit),
// which is not the same secret as the finished audit's — the response carries
// that one separately once the job succeeds.
export async function getAuditJob(
  jobId: string,
  token?: string | null,
): Promise<AuditJobStatus> {
  const q = token ? `?token=${encodeURIComponent(token)}` : "";
  const res = await request(
    `${API_BASE_URL}/v1/audit-jobs/${encodeURIComponent(jobId)}${q}`,
  );
  return parse<AuditJobStatus>(res);
}

// The audit and its report are ownership-gated by a per-row access token
// (delivered once at creation). It travels as a ?token=... query param so a
// shareable link carries it; without it the backend answers 404.
export async function getAudit(
  id: string,
  token?: string | null,
): Promise<PersistedAudit> {
  const q = token ? `?token=${encodeURIComponent(token)}` : "";
  const res = await request(
    `${API_BASE_URL}/v1/audits/${encodeURIComponent(id)}${q}`,
  );
  return parse<PersistedAudit>(res);
}

export function reportUrl(id: string, token?: string | null): string {
  const q = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${API_BASE_URL}/v1/audits/${encodeURIComponent(id)}/report${q}`;
}

export async function createUsdtInvoice(): Promise<UsdtInvoice> {
  const res = await request(`${API_BASE_URL}/v1/billing/usdt/invoice`, {
    method: "POST",
  });
  return parse<UsdtInvoice>(res);
}

export async function getUsdtInvoice(id: string): Promise<UsdtInvoiceStatus> {
  const res = await request(
    `${API_BASE_URL}/v1/billing/usdt/invoice/${encodeURIComponent(id)}`,
  );
  return parse<UsdtInvoiceStatus>(res);
}

// Open a USDT invoice to buy a Fix Pack for one specific audit. The returned
// invoice is polled with getUsdtInvoice, exactly like the Pro invoice.
export async function createFixpackUsdtInvoice(
  auditId: string,
): Promise<FixpackUsdtInvoice> {
  const res = await request(
    `${API_BASE_URL}/v1/audits/${encodeURIComponent(auditId)}/fixpack/usdt-invoice`,
    { method: "POST" },
  );
  return parse<FixpackUsdtInvoice>(res);
}

// Who the payer says they are. Both required by the backend: a card transfer
// carries no reference field, so the payer's name and email are the only thing
// the operator can match an incoming transfer against.
export interface PayerContact {
  payer_name: string;
  payer_email: string;
}

function payerBody(payer: PayerContact): RequestInit {
  return {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      payer_name: payer.payer_name.trim(),
      payer_email: payer.payer_email.trim(),
    }),
  };
}

// The published payment requisites for the footer. Public and uncached-by-us:
// the backend env is the single source, so a rotated card takes effect on the
// next page load with no rebuild.
export async function getBillingDetails(): Promise<BillingDetails> {
  const res = await request(`${API_BASE_URL}/v1/billing/details`);
  return parse<BillingDetails>(res);
}

// Open a bank-transfer invoice for Pro. The response carries the card number
// to pay and the reference code that identifies the order.
export async function createBankTransferInvoice(
  payer: PayerContact,
): Promise<BankTransferInvoice> {
  const res = await request(`${API_BASE_URL}/v1/billing/bank-transfer/pro`, {
    method: "POST",
    ...payerBody(payer),
  });
  return parse<BankTransferInvoice>(res);
}

// Same, scoped to one audit's Fix Pack. Polled with getBankTransferInvoice.
export async function createFixpackBankTransferInvoice(
  auditId: string,
  payer: PayerContact,
): Promise<BankTransferInvoice> {
  const res = await request(
    `${API_BASE_URL}/v1/audits/${encodeURIComponent(auditId)}/fixpack/bank-transfer`,
    { method: "POST", ...payerBody(payer) },
  );
  return parse<BankTransferInvoice>(res);
}

export async function getBankTransferInvoice(
  reference: string,
): Promise<BankTransferStatus> {
  const res = await request(
    `${API_BASE_URL}/v1/billing/bank-transfer/${encodeURIComponent(reference)}`,
  );
  return parse<BankTransferStatus>(res);
}

// "I've paid" — pages the operator to go look at their statement. Grants
// nothing on its own; the invoice stays pending until a human confirms.
export async function reportBankTransferPaid(
  reference: string,
): Promise<BankTransferPaidResult> {
  const res = await request(
    `${API_BASE_URL}/v1/billing/bank-transfer/${encodeURIComponent(reference)}/paid`,
    { method: "POST" },
  );
  return parse<BankTransferPaidResult>(res);
}

export async function getFixpackStatus(auditId: string): Promise<FixpackStatus> {
  const res = await request(
    `${API_BASE_URL}/v1/audits/${encodeURIComponent(auditId)}/fixpack-status`,
  );
  return parse<FixpackStatus>(res);
}

// Open a one-time PayPal order for Pro (product="pro") or a Fix Pack
// (product="fixpack", auditId required). Returns the order id the PayPal
// Buttons approve + capture against; the capture grants via our webhook.
export async function createPaypalOrder(
  product: "pro" | "fixpack",
  auditId?: string,
): Promise<PaypalOrder> {
  const res = await request(`${API_BASE_URL}/v1/paypal/orders`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ product, audit_id: auditId }),
  });
  return parse<PaypalOrder>(res);
}

// Poll one PayPal Pro order. Reveals the API key only once the webhook has
// captured and granted, exactly like getUsdtInvoice for USDT.
export async function getPaypalOrder(id: string): Promise<PaypalOrderStatus> {
  const res = await request(
    `${API_BASE_URL}/v1/paypal/orders/${encodeURIComponent(id)}`,
  );
  return parse<PaypalOrderStatus>(res);
}

// Open a recurring PayPal monitoring subscription for a repo. Returns the
// subscription id (the PayPal Buttons approve against it) and an approve URL.
export async function createPaypalSubscription(
  repoUrl: string,
): Promise<PaypalSubscription> {
  const res = await request(`${API_BASE_URL}/v1/paypal/subscriptions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repoUrl }),
  });
  return parse<PaypalSubscription>(res);
}

// Is the GitHub App installed on owner/repo? Checked before offering a Fix
// Pack, which opens a real PR and so needs the App on the target repo. When
// not installed, the response carries a ready-built install_url.
export async function getInstallationStatus(
  owner: string,
  repo: string,
): Promise<InstallationStatus> {
  const q = `?owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}`;
  const res = await request(
    `${API_BASE_URL}/v1/github/installation-status${q}`,
  );
  return parse<InstallationStatus>(res);
}
