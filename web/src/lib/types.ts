// Types mirror the FastAPI backend's real response shapes. Sources:
//   app/scan/scoring.py      -> Score
//   app/scan/pipeline.py     -> finding keys, score.basis
//   app/main.py create_audit -> AuditJobAccepted | AuditResult (POST /v1/audits)
//   app/main.py get_audit_job -> AuditJobStatus (GET /v1/audit-jobs/{id})
//   app/db.py _row_to_audit  -> PersistedAudit (GET /v1/audits/{id})
//   app/main.py get_account  -> Account (GET /v1/account)
//   app/billing/usdt_trc20.py invoice_status/create_invoice -> Usdt*

export type Severity = "critical" | "high" | "medium" | "low";

// Mirrors CATEGORIES in app/scan/scoring.py. "Correctness" and "Config" were
// removed there in #181 because no producer ever assigned them, so both scored
// a constant 10.0 while carrying 25% of the weight. Note this constant is
// currently referenced nowhere; it duplicates a backend list, which is how the
// two drift.
export const CATEGORY_NAMES = [
  "Security",
  "Auth",
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

// POST /v1/audits, cache hit — byte-identical content was audited before, so
// the backend answers with the stored result instead of queueing a scan.
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

// POST /v1/audits, the normal path — the submission is queued and the scan
// runs in the audit worker. Poll GET /v1/audit-jobs/{job_id}?token=...
export interface AuditJobAccepted {
  job_id: string;
  // The JOB's ownership token (not the audit's), delivered once here. It is
  // the only key to the poll endpoint.
  access_token: string | null;
  state: string;
}

export type CreateAuditResponse = AuditResult | AuditJobAccepted;

// A cache hit returns a finished audit; everything else returns a job to poll.
export function isAuditJobAccepted(
  r: CreateAuditResponse,
): r is AuditJobAccepted {
  return "job_id" in r;
}

// app/db.py migration 0022 -- created/queued/claimed/running are in flight,
// the rest are terminal.
export type AuditJobState =
  | "created"
  | "queued"
  | "claimed"
  | "running"
  | "succeeded"
  | "failed"
  | "timed_out"
  | "cancelled"
  | "dead_letter";

// GET /v1/audit-jobs/{job_id}?token=...
export interface AuditJobStatus {
  id: string;
  state: AuditJobState;
  // Machine-readable reason a terminal job has no result. Never shown raw.
  error_code: string | null;
  audit_id: string | null;
  // The finished AUDIT's own token — a different secret from the job token,
  // and the one GET /v1/audits/{id} wants. Null until the job succeeds.
  audit_access_token: string | null;
  created_at: string;
  completed_at: string | null;
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
  /**
   * Whether a Fix Pack could produce anything for this audit. Computed by the
   * API from the findings and the rules the Fix Pack knows how to rewrite --
   * not derivable here without copying that list into TypeScript, where it
   * would drift.
   *
   * Optional so an older API (or a cached response) simply reads as unknown.
   */
  fixpack_auto_fixable?: boolean;
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
  | {
      invoice_id: string;
      status: "completed";
      tier: "pro";
      // Delivered exactly once, on the first completed poll: the key is not
      // stored server-side, so a repeat poll of the same invoice gets null
      // here with key_already_delivered true. That is not an error — it means
      // the key already went out (to this page, or to Telegram /link).
      api_key: string | null;
      key_already_delivered?: boolean;
    }
  | { invoice_id: string; status: "expired" };

// POST /v1/audits/{audit_id}/fixpack/usdt-invoice — same shape as UsdtInvoice
// plus the audit this Fix Pack is scoped to. Polled via the same
// GET /v1/billing/usdt/invoice/{id} endpoint as the Pro invoice.
export interface FixpackUsdtInvoice extends UsdtInvoice {
  audit_id: string;
}

// The payer-facing bank fields. Served by GET /v1/billing/details and echoed
// in the invoice response, never published as NEXT_PUBLIC_* — the backend env
// stays the single source, so rotating the card needs no frontend rebuild.
export interface BankDetails {
  // The only field the checkout page shows: the payer copies this and pays.
  // The rest are the full requisites behind that card, rendered in the footer.
  card: string;
  bank_name: string;
  swift: string;
  beneficiary: string;
  account: string;
  address: string;
}

// POST /v1/billing/bank-transfer/pro and
// POST /v1/audits/{id}/fixpack/bank-transfer.
export interface BankTransferInvoice {
  payment_id: string;
  // Goes in the transfer's payment-reference field. THIS, not the amount, is
  // what the operator matches against the bank statement.
  reference: string;
  amount: string;
  currency: string;
  bank: BankDetails;
  expires_at: string;
  audit_id?: string;
}

// GET /v1/billing/details — public, unauthenticated, the single source for the
// requisites the footer renders. `bank` is null when the deployment has no
// bank transfer configured, and the footer then omits the block.
export interface BillingDetails {
  bank: BankDetails | null;
}

// GET /v1/pricing — what is on sale and what it costs. Read from the same
// accessor the invoice creator uses, so a price shown here cannot drift from
// the one charged at checkout. Fix Pack only and USD only, by product
// decision: the free tier is static-only and costs nothing to run, so the Pro
// tier's higher audit limit is not something we charge for.
export interface Pricing {
  fixpack: { amount: string; currency: string };
}

// GET /v1/billing/bank-transfer/{reference}. "expired" is cosmetic: the quote
// is stale, but the operator can still confirm a transfer that arrives later.
export type BankTransferStatus =
  | {
      reference: string;
      status: "pending";
      product: "pro_tier" | "fixpack";
      amount: string | null;
      currency: string;
      expires_at: string;
      bank?: BankDetails;
      audit_id?: string;
    }
  | {
      reference: string;
      status: "completed";
      product: "pro_tier";
      tier: "pro";
      // Same one-shot delivery as UsdtInvoiceStatus above.
      api_key: string | null;
      key_already_delivered?: boolean;
    }
  | {
      reference: string;
      status: "completed";
      product: "fixpack";
      audit_id?: string;
    }
  | { reference: string; status: "expired" };

// POST /v1/billing/bank-transfer/{reference}/paid — "I've paid". Grants
// nothing; `notified` says whether the operator's phone actually buzzed
// (false when alerting is unconfigured or the repeat was throttled).
export interface BankTransferPaidResult {
  reference: string;
  status: string;
  notified: boolean;
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
  // On "failed" only: "infrastructure" when the job never ran (sandbox-runner
  // outage or a crashed worker), so the text can avoid implying the client's
  // repo was at fault. null for a genuine generation failure, and for every
  // other status.
  failure_kind?: "infrastructure" | null;
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
  | {
      order_id: string;
      status: "completed";
      tier: "pro";
      // Same one-shot delivery as UsdtInvoiceStatus above.
      api_key: string | null;
      key_already_delivered?: boolean;
    };

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
