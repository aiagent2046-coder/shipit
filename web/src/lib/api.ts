// Thin fetch client for the Drydock FastAPI backend. No backend of our
// own — every call here is a cross-origin request to NEXT_PUBLIC_API_BASE_URL.

import type {
  Account,
  AuditResult,
  FixpackStatus,
  FixpackUsdtInvoice,
  PersistedAudit,
  UsdtInvoice,
  UsdtInvoiceStatus,
} from "./types";

export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || "https://45-10-40-169.sslip.io"
).replace(/\/+$/, "");

export const TELEGRAM_BOT_USERNAME =
  process.env.NEXT_PUBLIC_TELEGRAM_BOT_USERNAME || "";

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

export async function createAudit(
  input: { repoUrl?: string; file?: File },
  apiKey?: string | null,
): Promise<AuditResult> {
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
  return parse<AuditResult>(res);
}

export async function getAudit(id: string): Promise<PersistedAudit> {
  const res = await request(`${API_BASE_URL}/v1/audits/${encodeURIComponent(id)}`);
  return parse<PersistedAudit>(res);
}

export function reportUrl(id: string): string {
  return `${API_BASE_URL}/v1/audits/${encodeURIComponent(id)}/report`;
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

export async function getFixpackStatus(auditId: string): Promise<FixpackStatus> {
  const res = await request(
    `${API_BASE_URL}/v1/audits/${encodeURIComponent(auditId)}/fixpack-status`,
  );
  return parse<FixpackStatus>(res);
}
