// Types mirror the FastAPI backend's real response shapes. Sources:
//   app/scan/scoring.py      -> Score
//   app/scan/pipeline.py     -> finding keys, score.basis
//   app/main.py create_audit -> AuditResult (POST /v1/audits, 202)
//   app/db.py _row_to_audit  -> PersistedAudit (GET /v1/audits/{id})
//   app/main.py get_account  -> Account (GET /v1/account)
//   app/billing/usdt_trc20.py invoice_status/create_invoice -> Usdt*

export type Severity = "critical" | "high" | "medium" | "low";

export const CATEGORY_NAMES = [
  "Security",
  "Auth",
  "Correctness",
  "Config",
  "Testing",
  "Deploy",
] as const;

export interface Score {
  total: number;
  categories: Record<string, number>;
  basis?: "static+llm" | "static_only";
}

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  category: string;
  file?: string;
  line?: number;
  masked?: string;
  explanation?: string;
  fix_hint?: string;
}

// POST /v1/audits — completes inline (up to ~2 min) and returns the full result.
export interface AuditResult {
  audit_id: string;
  // Per-audit ownership token, delivered once at creation. Required as
  // ?token=... to read the audit or its report later. Null on an
  // unpersisted (no-DATABASE_URL) backend, where there's no stored row.
  access_token: string | null;
  persisted: boolean;
  status: string;
  stack: string;
  file_count: number;
  score: Score;
  findings: Finding[];
  // The GitHub URL the audit was run from, or null for zip uploads. Fix Pack
  // is only available when this is present (there's a repo to open a PR on).
  repo_url: string | null;
  llm: unknown;
}

// GET /v1/audits/{id} — the persisted DB row (different key names).
export interface PersistedAudit {
  id: string;
  stack: string;
  status: string;
  file_count: number;
  score_total: number | null;
  score_json: Score | null;
  findings_json: Finding[] | null;
  repo_url: string | null;
  created_at: string;
}

export interface Entitlements {
  daily_audit_limit: number;
  private_repos_allowed: boolean;
  priority_queue: boolean;
}

export interface Account {
  tier: "free" | "pro";
  authenticated: boolean;
  entitlements: Entitlements;
}

export interface UsdtInvoice {
  invoice_id: string;
  network: string;
  address: string;
  amount: number;
  currency: string;
  expires_at: string;
}

export type UsdtInvoiceStatus =
  | {
      invoice_id: string;
      status: "pending";
      network: string;
      address: string;
      amount: number;
      currency: string;
      expires_at: string;
    }
  | { invoice_id: string; status: "completed"; tier: "pro"; api_key: string | null }
  | { invoice_id: string; status: "expired" };

// POST /v1/audits/{audit_id}/fixpack/usdt-invoice — same shape as UsdtInvoice
// plus the audit this Fix Pack is scoped to. Polled via the same
// GET /v1/billing/usdt/invoice/{id} endpoint as the Pro invoice.
export interface FixpackUsdtInvoice extends UsdtInvoice {
  audit_id: string;
}

// fixpack_jobs status progression (app/db.py). null = no purchase yet.
// "paid" = purchased, waiting in the backlog; "running" = the processor
// has claimed it and is generating the fix (both shown as in-progress).
export type FixpackJobStatus =
  | "paid"
  | "running"
  | "delivered"
  | "no_fix_needed"
  | "blocked"
  | "failed";

// GET /v1/audits/{audit_id}/fixpack-status
export interface FixpackStatus {
  audit_id: string;
  status: FixpackJobStatus | null;
  pr_url: string | null;
}

// POST /v1/paypal/orders — a one-time PayPal order (Pro or Fix Pack). The
// browser's PayPal Buttons approve + capture against `order_id`; the capture
// then arrives at our webhook and grants. Poll GET /v1/paypal/orders/{id}.
export interface PaypalOrder {
  order_id: string;
  status: string;
  amount: string;
  currency: string;
  product: "pro" | "fixpack";
  audit_id?: string;
}

// GET /v1/paypal/orders/{id} — reveals the API key only once the webhook has
// captured and granted (Pro). A pending order never carries a key.
export type PaypalOrderStatus =
  | { order_id: string; status: "pending" }
  | { order_id: string; status: "completed"; tier: "pro"; api_key: string | null };

// POST /v1/paypal/subscriptions — a recurring monitoring subscription. The
// browser sends the buyer to `approve_url` (or approves via the SDK button);
// PayPal then delivers the ACTIVATED / SALE webhooks.
export interface PaypalSubscription {
  subscription_id: string;
  approve_url: string | null;
  status: string;
}

// GET /v1/github/installation-status?owner=&repo=
// A Fix Pack opens a real PR, which needs the GitHub App installed on the
// target repo. `app_configured=false` means this deployment has no App at
// all (installed is null) — the frontend shouldn't gate in that case.
export interface InstallationStatus {
  owner: string;
  repo: string;
  app_configured: boolean;
  installed: boolean | null;
  install_url: string | null;
}
