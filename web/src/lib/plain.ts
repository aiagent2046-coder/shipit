import type { Finding } from "./types";
import { isNonProductionFinding } from "./evidence";

// Mirrors app/report/plain_language.py.
const PLAIN: Record<string, { what: string; risk: string; fix: string }> = {
  "python-route-read-auth-consistency": {"what": "Object lookup differs from protected sibling routes.", "risk": "A local route uses a different lookup from protected sibling routes. Global authorization is unresolved.", "fix": "Check ownership authorization and reproduce missing/wrong-token access using synthetic records."},
  "aws-access-key-id": {
    "what": "A value matches the AWS access key ID format.",
    "risk": "An access key ID alone cannot authenticate AWS requests; a matching secret access key is also required. This scan has not checked validity or permissions.",
    "fix": "Check whether this is synthetic. If a real credential pair was exposed, revoke it and move its replacement outside the repository."
  },
  "github-pat": {
    "what": "A value matches a GitHub token format.",
    "risk": "If this is a valid token, its permissions may allow access to repositories. The scan has not checked validity, scope or expiry.",
    "fix": "Confirm whether the value is synthetic. Revoke an exposed real token and store its replacement outside the repository."
  },
  "stripe-live-key": {
    "what": "A value matches a Stripe live-key format.",
    "risk": "A valid key may allow payment operations within its permissions. A format match does not establish that this key works or which operations it permits.",
    "fix": "Check whether this is a fixture. Rotate an exposed real key and store its replacement in server configuration."
  },
  "anthropic-api-key": {
    "what": "A value matches an Anthropic API key format.",
    "risk": "If valid, the key may permit billed API calls. This scan has not tested the credential or established access to an account.",
    "fix": "Check whether the value is synthetic. Revoke an exposed real key and store its replacement outside the repository."
  },
  "telegram-bot-token": {
    "what": "A value matches a Telegram bot token format.",
    "risk": "If valid, a token may allow bot API operations. Its validity and the scope of accessible messages have not been checked.",
    "fix": "Check whether this is a fixture. Revoke an exposed real token through BotFather and store the replacement outside the repository."
  },
  "private-key-block": {
    "what": "A private-key marker appears in the source.",
    "risk": "The marker may be a test string or part of a usable private key. Completeness, validity and deployment use have not been checked.",
    "fix": "Inspect the surrounding material without publishing it. Rotate an exposed real key and keep its replacement outside the repository."
  },
  "jwt-in-code": {
    "what": "A value resembles a JWT in the source.",
    "risk": "A valid, unexpired token may grant its associated permissions. This scan has not verified its signature, expiry or acceptance by a service.",
    "fix": "Check whether this is a test token. Invalidate an exposed real session token and avoid committing replacements."
  },
  "sql-secret-assignment": {
    "what": "A SQL-style assignment contains a credential-like value.",
    "risk": "This may be SQL code, a quoted example or a test fixture. The scan has not established that the value is real or used by a deployed database.",
    "fix": "Check the context and use of the value. Rotate an exposed real secret and read its replacement from server configuration."
  },
  "generic-assignment": {
    "what": "An assignment contains a credential-like value.",
    "risk": "The name and value match a secret pattern. This does not establish that the value is a live credential or that a service accepts it.",
    "fix": "Check the value and context. Rotate an exposed real credential; synthetic test data does not require account-level rotation."
  },
  "connection-string-password": {
    "what": "A connection URI contains a password-like value.",
    "risk": "If it names a reachable database and valid credentials, it may permit access within that database account's permissions. Reachability, validity and grants are not checked.",
    "fix": "Check whether this is a fixture. If real database credentials were exposed, change the password and move configuration outside the repository."
  },
  "connection-string-dev-password": {
    "what": "A connection string in your project uses a default password like `postgres` or `change_me`.",
    "risk": "This is the value tutorials and docker-compose files ship with, so it is almost certainly your local development database and not a leak. It is worth knowing about for one reason: if that same default is ever pointed at a real database, the password is already public knowledge.",
    "fix": "Nothing to do if this is your local setup. If anything real ever uses it, give it a proper password and move the connection string to an environment variable."
  },
  "env-file-committed": {
    "what": "An environment configuration file is included in the archive.",
    "risk": "Such files may contain configuration or credentials. File presence alone does not establish that a real secret was exposed.",
    "fix": "Inspect the contents. Keep private environment files outside version control and rotate any exposed real credentials."
  },
  "connection-string-local-host": {
    "what": "A local or development connection URI contains a password-like value.",
    "risk": "The hostname suggests a local or container service, but deployment and password reuse have not been checked. This is not evidence of public database access.",
    "fix": "Check whether this value is synthetic or reused on a real service. Rotate exposed real credentials where they are used."
  },
  "supabase-demo-key": {
    "what": "This is Supabase's local-development demo key, which ships with every project.",
    "risk": "It is not a key to your database. `supabase start` prints this same token for every developer, and the secret it is signed with is published in Supabase's own documentation — so anyone can produce an identical one, which is what makes it open nothing. The keys that must stay secret are the service_role key and the database password from your real project's dashboard, and those look the same to the eye.",
    "fix": "Nothing to rotate — there is no account behind this token. Do check that the key your deployed app actually uses comes from an environment variable and not from a committed file, because that one would matter."
  },
  "supabase-anon-key": {
    "what": "Your Supabase anon (public) key appears in the code.",
    "risk": "This particular key is meant to be public — it ships in every app's front-end by design, so this is informational, not a breach. Seeing it in many committed files usually just means the same key was pasted around; the keys that must stay secret are the service_role key and database passwords, which are NOT flagged here.",
    "fix": "No urgent action needed for the anon key itself. Do confirm your Row Level Security is on, since the anon key relies on it."
  },
  "gitignore-missing-secrets": {
    "what": "Your project has no .gitignore rule covering secret files like .env, private keys, or credential files.",
    "risk": "Without it, the next time you run `git add` it's easy to commit your .env or a key file by accident — handing every password and API key to anyone who can see the code. This is the most common way secrets end up leaked.",
    "fix": "Add a .gitignore that lists .env, .env.*, *.pem, *.key and other credential files so they can never be committed by mistake."
  },
  "no-tests": {
    "what": "The project has no automated tests.",
    "risk": "Every change is a blind edit: things that worked yesterday can silently break today, and you'll learn it from your users.",
    "fix": "Start with a few tests for the money paths — signup, login, checkout."
  },
  "dependency-dir-committed": {
    "what": "Installed libraries are stored in your repository as if you wrote them.",
    "risk": "Every clone downloads all of it, every update to a library lands in your history, and what is stored slowly stops matching what your lockfile says the project needs — so the versions running in production drift away from the ones you think you have.",
    "fix": "Add the folder to .gitignore and untrack it with `git rm -r --cached <folder>`. Your local copy stays; anyone cloning reinstalls from your lockfile, which is what it is for."
  },
  "no-dockerfile": {
    "what": "No Dockerfile was found in the supplied archive.",
    "risk": "A Dockerfile is one deployment option. Its absence does not establish that the app cannot run on a server; systemd and managed platforms are other options.",
    "fix": "Review the existing deployment instructions. Add a Dockerfile only if container deployment is needed."
  },
  "missing-error-boundary": {
    "what": "Your app has no error boundary above its pages.",
    "risk": "When any single component hits an error while rendering, there is nothing to contain it: the whole screen goes blank and the person using it can only reload and hope. One small bug anywhere becomes a total outage of the page.",
    "fix": "Add an error boundary above your routes. In the Next.js app router, create app/error.tsx and app/global-error.tsx; in a plain React app, wrap the top-level component in an <ErrorBoundary> with a small fallback that offers a reload."
  },
  "no-ci": {
    "what": "No automated checks run when the code changes (no CI).",
    "risk": "Broken changes reach your live app with nothing in the way.",
    "fix": "Add a simple GitHub Actions workflow that runs the tests on every change."
  }
};
const CREDENTIAL_RULES = new Set(["telegram-bot-token", "aws-access-key-id", "stripe-live-key", "private-key-block", "connection-string-password", "github-pat", "jwt-in-code", "connection-string-local-host", "anthropic-api-key", "generic-assignment", "sql-secret-assignment"]);

export function plainFields(finding: Finding): { what: string; risk: string; fix: string } {
  const rid = finding.rule_id || "";
  const base = PLAIN[rid];
  if (base && CREDENTIAL_RULES.has(rid)) {
    let { risk, fix } = base;
    if (isNonProductionFinding(finding)) {
      risk = "Found in a test, example or comment context. " + risk;
      fix = "Verify that this value is synthetic. " + fix;
    }
    if (finding.occurrence_count && finding.occurrence_count > 1) {
      risk += ` ${finding.occurrence_count} occurrences are recorded; inspect each location.`;
      if (finding.occurrence_files?.length) risk += ` Files: ${finding.occurrence_files.join(", ")}.`;
    }
    return { ...base, risk, fix };
  }
  if (rid === "no-dockerfile") return base;
  if (base) return { ...base, risk: finding.explanation || base.risk, fix: finding.fix_hint || base.fix };
  return { what: finding.title || "", risk: finding.explanation || "", fix: finding.fix_hint || "" };
}
