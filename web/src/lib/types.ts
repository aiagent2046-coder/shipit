// Types mirror the FastAPI backend's real response shapes. Sources:
//   app/scan/scoring.py      -> Score
//   app/scan/pipeline.py     -> finding keys, score.basis
//   app/main.py create_audit -> AuditJobAccepted | AuditResult (POST /v1/audits)
//   app/main.py get_audit_job -> AuditJobStatus (GET /v1/audit-jobs/{id})
//   app/db.py _row_to_audit  -> PersistedAudit (GET /v1/audits/{id})
//   app/main.py get_account  -> Account (GET /v1/account)

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

// Why the safety gate capped the total, as recorded by the scorer that
// decided it (_gate_reasons in app/scan/scoring.py). Not re-derived here:
// working it out on this side needs the threshold, the gated category list
// and the confidence floor, and a second copy of that rule will not stay in
// agreement with the first.
export interface GateReason {
  // "unaudited_deployment" is the third route into the gate and the only
  // one that is not a statement about the code: it says the report may not
  // be about what runs. See SCOPE_INVALIDATING_RULE_IDS in
  // app/scan/scoring.py.
  kind: "subscore" | "critical" | "unaudited_deployment";
  category: string;
  value?: number; // subscore only
  rule_id?: string; // critical only
  title?: string; // critical only
}

export interface Score {
  total: number;
  categories: Record<string, number>;
  // Every value app/scan/pipeline.py can emit: BASIS_FULL, BASIS_PREVIEW,
  // BASIS_PARTIAL, BASIS_STATIC_ONLY. The union listed only two of them, and
  // that omission is the whole reason the free-tier bug lived: TypeScript
  // rejected `basis !== "static+preview"` as a comparison with no overlap, so
  // the predicate that decides whether a score may be published could not be
  // written correctly even by someone looking straight at it. A type that
  // under-describes the wire makes the honest branch unwriteable.
  //
  // "static+partial" is a full audit whose rubric run was cut short. It is
  // NOT free, and it must keep its score -- it is listed here so the union
  // matches the backend, not so it joins the free tier.
  basis?: "static+llm" | "static+partial" | "static+preview" | "static_only";
  // Optional because audits stored before this key existed have none, which
  // means "unknown", not "ungated" — an empty array is the ungated case.
  gated_by?: GateReason[];
  // Categories excluded from the mean because nothing produced findings for
  // them (a static-only scan cannot fill Auth or Money & Data). They still
  // appear in `categories` at 10.0, so a renderer MUST consult this before
  // drawing a bar. Absent on audits stored before the key existed.
  unexamined?: string[];
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
}

export interface Account {
  tier: "free" | "pro";
  authenticated: boolean;
  entitlements: Entitlements;
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
// the one charged at checkout. Fix Pack only, by product decision: the free
// tier is static-only and costs nothing to run, so the Pro tier's higher audit
// limit is not something we charge for.
//
// `currency` is an ISO code the backend sends -- roubles since 2026-08-23 --
// and it is never assumed at the point of display. Render it through
// formatMoney: this field once said "USD only", and a page that had internalised
// that printed "$990.00 RUB" for four days after the switch.
export interface Pricing {
  fixpack: { amount: string; currency: string };
  // Which rails are live on this deployment. Absent on an older API, which
  // the storefront reads as "card off, transfer on" -- the state every
  // deployment was in before ЮKassa existed.
  methods?: { card: boolean; bank_transfer: boolean };
}

// POST /v1/audits/{id}/fixpack/yookassa. Everything needed to send the buyer
// to the payment page and to name their order afterwards.
export interface CardPayment {
  reference: string;
  amount: string;
  currency: string;
  // Always https, and checked as such by the backend before it is returned
  // (app/billing/yookassa.py::confirmation_url) -- this value navigates a
  // browser, so it is not somewhere to trust a provider's response shape.
  confirmation_url: string;
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
      // Delivered exactly once, on the first completed poll: the key is
      // not stored server-side, so a repeat poll gets null here with
      // key_already_delivered true. That is not an error — it means the
      // key already went out (to this page, or to Telegram /link).
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

// POST /v1/audits/{id}/rls-check — the one consented request the product makes
// against a customer's own database.
//
// `status` is the load-bearing field and there are only two values, neither of
// which means "your database is fine": "checked" (we asked) and "refused" (we
// did not, and `reason` says why).
export interface RlsAttempt {
  // "success" = rows came back. "failure" = we asked and got none, which is
  // NOT the same as protected. "skipped"/"error" = the request settled nothing.
  status: string;
  detail: string;
  evidence: Record<string, unknown>;
}

export interface RlsCheckResult {
  persisted: boolean;
  status: "checked" | "refused";
  reason: string;
  project_ref: string;
  // "repository" (we found the key) or "supplied" (the customer handed it over).
  key_source: string;
  checked: string[];
  // Named, not counted: "we checked 12 of your 40" is a different report from
  // "we checked your tables".
  not_checked: string[];
  exposed_tables: string[];
  // Requests that settled nothing — a rejected key, a 5xx.
  inconclusive: number;
  // Answers that came back empty and CANNOT be read as protection: RLS filters
  // rather than denying, so a protected table and an empty one answer alike.
  empty_but_unproven: number;
  max_tables: number;
  attempts: RlsAttempt[];
}
