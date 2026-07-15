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
  persisted: boolean;
  status: string;
  stack: string;
  file_count: number;
  score: Score;
  findings: Finding[];
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
