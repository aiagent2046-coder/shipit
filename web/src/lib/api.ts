// Thin fetch client for the Drydock FastAPI backend. No backend of our
// own — every call here is a cross-origin request to NEXT_PUBLIC_API_BASE_URL.

import type {
  Account,
  AuditJobStatus,
  AuditResult,
  BankTransferInvoice,
  CardPayment,
  BankTransferPaidResult,
  BankTransferStatus,
  BillingDetails,
  CreateAuditResponse,
  FixpackStatus,
  InstallationStatus,
  PersistedAudit,
  Pricing,
  RlsCheckResult,
} from "./types";

export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000"
).replace(/\/+$/, "");

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

// Sent on every call, value irrelevant. A header outside the CORS-safelisted
// set forces a preflight, and the preflight is answered against the backend's
// origin allowlist -- which is what stops another site from riding along on
// the session cookie. See CSRF_HEADER in app/accounts.py.
const CSRF_HEADER = "X-Drydock-Web";

// No Authorization branch any more: the page cannot read the key, so it can
// never set that header. The backend still accepts it -- that path is for
// scripts and curl -- but nothing in this app has a key to put there.
function authHeaders(): Record<string, string> {
  return { [CSRF_HEADER]: "1" };
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
      // `service_paused` is the one reason whose `detail` is operator-authored
      // free text -- the note typed into service_flags when engaging the
      // emergency stop. Surfacing it verbatim showed a visitor our internal
      // state. Replaced here rather than in each component so a future caller
      // cannot reintroduce the leak by forgetting to special-case it.
      message =
        d.reason === "service_paused"
          ? "Drydock is paused for maintenance right now. Nothing was charged " +
            "and nothing was started. Try again shortly, or email " +
            "support@drydock.co if it stays paused."
          : d.detail || d.reason || message;
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
    // The session cookie is HttpOnly, so this is the only way it travels:
    // the page cannot attach it by hand even if it wanted to.
    return await fetch(input, { ...init, credentials: "include" });
  } catch (e) {
    throw new ApiError(
      `Could not reach the backend at ${API_BASE_URL}. It may be down, or ` +
        `this site's origin may not be allowed by the backend's CORS config.`,
      0,
      "network_error",
    );
  }
}

// Trade an API key for a session cookie the page cannot read. Answers with
// the same shape as getAccount, so a successful login needs no follow-up
// request. Throws ApiError(401) when the key is not recognized.
export async function login(apiKey: string): Promise<Account> {
  const res = await request(`${API_BASE_URL}/v1/auth/login`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: apiKey.trim() }),
  });
  return parse<Account>(res);
}

// Drop the session cookie. Must be a request: an HttpOnly cookie can only be
// cleared by the server that set it.
export async function logout(): Promise<void> {
  await request(`${API_BASE_URL}/v1/auth/logout`, {
    method: "POST",
    headers: { ...authHeaders() },
  });
}

export async function getAccount(): Promise<Account> {
  const res = await request(`${API_BASE_URL}/v1/account`, {
    headers: { ...authHeaders() },
  });
  return parse<Account>(res);
}

// Submits an audit. The scan itself runs in the backend's audit worker, so the
// normal answer is an AuditJobAccepted to poll with getAuditJob; the exception
// is a content-cache hit, which comes back as a finished AuditResult. Use
// isAuditJobAccepted to tell them apart.
export async function createAudit(
  input: { repoUrl?: string; file?: File },
): Promise<CreateAuditResponse> {
  const form = new FormData();
  if (input.file) {
    form.append("archive", input.file);
  } else if (input.repoUrl) {
    form.append("repo_url", input.repoUrl);
  }
  const res = await request(`${API_BASE_URL}/v1/audits`, {
    method: "POST",
    headers: { ...authHeaders() },
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

// Who the payer says they are. Both required by the backend: a card transfer
// carries no reference field, so the payer's name and email are the only thing
// the operator can match an incoming transfer against.
export interface PayerContact {
  payer_name: string;
  payer_email: string;
  // Optional. Blank is sent as null rather than "" so the backend and a SQL
  // `is null` agree about what "no X handle" means.
  payer_x?: string;
  // What language to write to this payer in, recorded on the payment because
  // it cannot be recovered later: the operator confirms hours after this tab
  // closed. See migration 0033.
  payer_locale?: string;
}

function payerBody(payer: PayerContact): RequestInit {
  return {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      payer_name: payer.payer_name.trim(),
      payer_email: payer.payer_email.trim(),
      payer_x: payer.payer_x?.trim() || null,
      payer_locale: payer.payer_locale?.trim() || null,
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

// What things cost. Fetched rather than baked into the build for the same
// reason as the requisites above: the backend accessor the invoice creator
// calls is the single source, so the page can never advertise a figure that
// checkout then contradicts.
export async function getPricing(): Promise<Pricing> {
  const res = await request(`${API_BASE_URL}/v1/pricing`);
  return parse<Pricing>(res);
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

/**
 * Open a card payment for one audit's Fix Pack and get the URL to send the
 * buyer to. Nothing is charged here: ЮKassa's own page takes the card.
 *
 * `returnToken` is the audit's access token, passed so the payer comes back to
 * a page they can actually read. It is sent as a token rather than as a return
 * URL on purpose -- see CardPayer in app/routes/yookassa.py.
 */
export async function createFixpackCardPayment(
  auditId: string,
  payer: PayerContact,
  returnToken: string | null,
): Promise<CardPayment> {
  const body = payerBody(payer);
  const res = await request(
    `${API_BASE_URL}/v1/audits/${encodeURIComponent(auditId)}/fixpack/yookassa`,
    {
      method: "POST",
      headers: body.headers,
      body: JSON.stringify({
        ...JSON.parse(body.body as string),
        return_token: returnToken,
      }),
    },
  );
  return parse<CardPayment>(res);
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

export async function getFixpackStatus(auditId: string, token: string): Promise<FixpackStatus> {
  const res = await request(
    `${API_BASE_URL}/v1/audits/${encodeURIComponent(auditId)}/fixpack-status?token=${encodeURIComponent(token)}`,
  );
  return parse<FixpackStatus>(res);
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

// POST /v1/audits/{id}/rls-check — ask the customer's own Supabase project,
// with its public key, whether it hands out rows it should not.
//
// `consent` is passed through from what the customer TYPED. It is deliberately
// not a constant this function supplies: the backend demands an exact phrase
// precisely because a boolean is what a client sets by default, and a UI that
// hardcoded the phrase behind a click would be that boolean with extra steps.
export async function runRlsCheck(
  auditId: string,
  input: { consent: string; token?: string | null; anonKey?: string },
): Promise<RlsCheckResult> {
  const form = new FormData();
  form.append("consent", input.consent);
  if (input.token) form.append("token", input.token);
  if (input.anonKey) form.append("anon_key", input.anonKey);
  const res = await request(
    `${API_BASE_URL}/v1/audits/${encodeURIComponent(auditId)}/rls-check`,
    { method: "POST", headers: { ...authHeaders() }, body: form },
  );
  return parse<RlsCheckResult>(res);
}
