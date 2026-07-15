import type { Finding } from "./types";

// Mirror of app/report/plain_language.py PLAIN. Kept in sync with the
// backend so static findings (whose plain-language text is applied
// server-side only in the HTML report) also read meaningfully in this
// UI's findings list. LLM findings carry their own explanation/fix_hint
// and don't need this table.
const PLAIN: Record<string, { what: string; risk: string; fix: string }> = {
  "aws-access-key-id": {
    what: "An Amazon Web Services key is written directly in your code.",
    risk: "Anyone who sees your code can use your AWS account: run servers on your credit card, read your stored files, or delete them. Leaked AWS keys are typically abused within minutes of reaching a public repo.",
    fix: "Remove the key from the code, revoke it in AWS right away, and keep the new one in environment variables.",
  },
  "github-pat": {
    what: "A GitHub access token is written directly in your code.",
    risk: "Whoever finds it can read and change your repositories as you — including pushing malicious code your users would then run.",
    fix: "Revoke the token on GitHub and move the new one to environment variables.",
  },
  "stripe-live-key": {
    what: "A live Stripe payment key is written directly in your code.",
    risk: "This key moves real money. Anyone who finds it can issue refunds, read customer payment data, or create charges.",
    fix: "Roll the key in the Stripe dashboard immediately and keep the new one in environment variables.",
  },
  "anthropic-api-key": {
    what: "An AI provider (Anthropic) key is written directly in your code.",
    risk: "Anyone who finds it can make AI requests on your account and run up your bill until the provider blocks it.",
    fix: "Revoke the key and keep the new one in environment variables.",
  },
  "telegram-bot-token": {
    what: "A Telegram bot token is written directly in your code.",
    risk: "Whoever finds it fully controls your bot: they can read its messages and impersonate it to your users.",
    fix: "Revoke the token via @BotFather and keep the new one in environment variables.",
  },
  "private-key-block": {
    what: "A private cryptographic key is committed inside the repository.",
    risk: "Private keys are the master secret behind encryption or server access. Anyone with your code can decrypt what it protects or log in to what it opens.",
    fix: "Remove it from the repository, rotate the key, and store keys outside the codebase.",
  },
  "jwt-in-code": {
    what: "A login token (JWT) is committed inside the repository.",
    risk: "Depending on the token's power, someone could act as a logged-in user — or as an administrator — of your app without a password.",
    fix: "Remove it, invalidate the session it belongs to, and never commit real tokens.",
  },
  "sql-secret-assignment": {
    what: "A password or secret is written inside a database migration file.",
    risk: "Migration files live in your code forever — everyone with the code gets the secret, and 'deleting' it later doesn't remove it from the project's history.",
    fix: "Move the secret to server-side configuration and rotate it; the migration should read it from settings, not contain it.",
  },
  "generic-assignment": {
    what: "A password or secret appears to be written directly in your code.",
    risk: "Anything committed to code ends up in backups, on GitHub, and on every laptop that clones the project. It's like taping the office key to the front door.",
    fix: "Move it to environment variables and rotate the leaked value.",
  },
  "env-file-committed": {
    what: "Your .env file — the file that holds ALL your secrets — is inside the repository.",
    risk: "The .env file usually contains database passwords and API keys in one place. Committing it hands your entire keychain to anyone who ever sees the code.",
    fix: "Remove it from the repository, add .env to .gitignore, and rotate every secret that was inside.",
  },
  "supabase-anon-key": {
    what: "Your Supabase anon (public) key appears in the code.",
    risk: "This particular key is meant to be public — it ships in every app's front-end by design, so this is informational, not a breach. The keys that must stay secret are the service_role key and database passwords, which are NOT flagged here.",
    fix: "No urgent action needed for the anon key itself. Do confirm your Row Level Security is on, since the anon key relies on it.",
  },
  "no-tests": {
    what: "The project has no automated tests.",
    risk: "Every change is a blind edit: things that worked yesterday can silently break today, and you'll learn it from your users.",
    fix: "Start with a few tests for the money paths — signup, login, checkout.",
  },
  "no-dockerfile": {
    what: "The app isn't packaged to run on a server (no Dockerfile).",
    risk: "It runs on the builder's platform, but moving to your own hosting — often needed for cost or control — will be a wall.",
    fix: "Add a Dockerfile; our Deploy Pack generates a working one automatically.",
  },
  "no-ci": {
    what: "No automated checks run when the code changes (no CI).",
    risk: "Broken changes reach your live app with nothing in the way.",
    fix: "Add a simple GitHub Actions workflow that runs the tests on every change.",
  },
};

export function plainFields(finding: Finding): {
  what: string;
  risk: string;
  fix: string;
} {
  const rid = finding.rule_id || "";
  if (PLAIN[rid]) {
    const base = PLAIN[rid];
    const note = (finding.explanation || "").trim();
    return { ...base, risk: note ? `${base.risk} ${note}` : base.risk };
  }
  return {
    what: finding.title || "",
    risk: finding.explanation || "",
    fix: finding.fix_hint || "",
  };
}
