import type { AuditResult, Finding } from "./types";

// A realistic-SHAPED example audit for the landing page's zero-interaction
// demo. It is NOT a real user's result — it's clearly labeled "Example
// report" in the UI. rule_ids are real ones from
// app/report/plain_language.py so the what/risk/fix copy matches exactly
// what the live backend would render; confidences/scores are plausible
// values for a typical vibe-coded Next.js app, not fabricated extremes.
export const DEMO_FINDINGS: Finding[] = [
  {
    rule_id: "stripe-live-key",
    title: "Hardcoded Stripe live secret key",
    severity: "critical",
    confidence: 0.98,
    category: "Security",
    file: "app/api/checkout/route.ts",
    line: 12,
    masked: "sk_live_51Nc…9aQ2",
    explanation: "",
    fix_hint: "",
  },
  {
    rule_id: "env-file-committed",
    title: ".env committed to the repository",
    severity: "critical",
    confidence: 0.95,
    category: "Security",
    file: ".env",
    line: 1,
    masked: "",
    explanation: "",
    fix_hint: "",
  },
  {
    rule_id: "supabase-anon-key",
    title: "Supabase anon key present in client code",
    severity: "high",
    confidence: 0.8,
    category: "Auth",
    file: "lib/supabaseClient.ts",
    line: 4,
    masked: "eyJhbGciOiJI…",
    explanation: "",
    fix_hint: "",
  },
  {
    rule_id: "no-tests",
    title: "No automated tests found",
    severity: "medium",
    confidence: 0.9,
    category: "Testing",
    file: "",
    line: 0,
    masked: "",
    explanation: "",
    fix_hint: "",
  },
  {
    rule_id: "no-dockerfile",
    title: "No Dockerfile",
    severity: "low",
    confidence: 0.85,
    category: "Deploy",
    file: "",
    line: 0,
    masked: "",
    explanation: "",
    fix_hint: "",
  },
  {
    rule_id: "no-ci",
    title: "No CI workflow",
    severity: "low",
    confidence: 0.7,
    category: "Config",
    file: "",
    line: 0,
    masked: "",
    explanation: "",
    fix_hint: "",
  },
];

export const DEMO_AUDIT: AuditResult = {
  audit_id: "example-0000-demo",
  // Demo is a canned, unpersisted result -- no real row, so no token.
  access_token: null,
  persisted: false,
  status: "completed",
  stack: "nextjs",
  file_count: 128,
  score: {
    total: 4.6,
    categories: {
      Security: 1.8,
      Auth: 6.2,
      Correctness: 8.0,
      Config: 7.4,
      Testing: 6.4,
      Deploy: 8.5,
    },
    basis: "static+llm",
  },
  findings: DEMO_FINDINGS,
  repo_url: "https://github.com/example/demo-app",
  llm: { basis: "static+llm" },
};
