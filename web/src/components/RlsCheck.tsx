"use client";

/**
 * The one action in this product that touches a database belonging to somebody.
 *
 * Everything else here reads a copy of the customer's code. This sends real
 * requests to their live Supabase project, so the block is shaped around three
 * things the customer has to be able to see BEFORE agreeing:
 *
 *   what will happen  — up to N read-only requests with the key that already
 *                       ships to every visitor's browser
 *   what it can find  — rows coming back, which is evidence
 *   what it cannot    — an empty answer, which is not proof of protection
 *
 * CONSENT IS TYPED, NOT CLICKED. The backend demands the exact phrase because
 * a boolean is what a client library sets by default. A UI that hardcoded the
 * phrase and sent it on a button press would be that boolean with extra steps,
 * so the input below is the customer's own keystrokes and the value posted is
 * whatever they wrote. It is the same reason GitHub makes you type a
 * repository's name to delete it.
 */

import { useState } from "react";
import { runRlsCheck, ApiError } from "@/lib/api";
import type { RlsAccessReviewInput, RlsAttempt, RlsCheckResult } from "@/lib/types";
import { Spinner } from "./Spinner";
import { RlsMetadataInput, RlsMetadataOutcome } from "./RlsMetadata";

const CONSENT_PHRASE = "i-own-this-project";
const PROJECT_URL = /^https:\/\/([a-z0-9]{16,32})\.supabase\.co\/?$/i;

// Read only the public JWT claims to catch common input mistakes. Supabase
// verifies the key when it receives a request; this is not authentication.
function legacyClaims(key: string): { role?: unknown; ref?: unknown } | null {
  const parts = key.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const claims: unknown = JSON.parse(atob(payload.padEnd(Math.ceil(payload.length / 4) * 4, "=")));
    return claims && typeof claims === "object" ? claims : null;
  } catch {
    return null;
  }
}

function keyInputError(key: string, projectRef?: string): string | null {
  if (key.length > 4096) return "This key is too long. Copy only your project's public API key.";
  const claims = legacyClaims(key);
  if (key.startsWith("sb_secret_") || claims?.role === "service_role") {
    return "Use a public publishable or legacy anon key. Secret and service_role keys are not accepted.";
  }
  if (key.startsWith("sb_publishable_") && !/^sb_publishable_[A-Za-z0-9_-]+$/.test(key)) {
    return "Enter the complete public publishable key from your Supabase project.";
  }
  if (projectRef && typeof claims?.ref === "string" && claims.ref !== projectRef) {
    return "The Project URL and legacy anon key belong to different projects.";
  }
  return null;
}

/** Why the button is off, said about what the reader actually typed.
 *
 * "That is not the confirmation phrase" is true of every wrong value and
 * therefore explains none of them. The three cases below are the three that
 * have happened or will: nothing typed, the repository URL pasted in (twice,
 * by the same customer), and a phrase that differs only in case — which a
 * phone keyboard produces on its own and which is invisible to the person
 * reading their own screen.
 */
function unmetReason(typed: string): React.ReactNode {
  const value = typed.trim();
  if (value === "") {
    return (
      <>
        Type <code className="font-mono">{CONSENT_PHRASE}</code> above to enable
        the button.
      </>
    );
  }
  if (/^(https?:\/\/|git@)/i.test(value) || value.includes("github.com")) {
    return (
      <>
        That is your repository&apos;s address — you do not need to paste it, we
        already read it from this audit. This box wants the words{" "}
        <code className="font-mono">{CONSENT_PHRASE}</code>.
      </>
    );
  }
  if ((value.startsWith("ey") && value.length > 40) || value.startsWith("sb_")) {
    return (
      <>
        That looks like your key — it goes in the field above. This box wants
        the words <code className="font-mono">{CONSENT_PHRASE}</code>.
      </>
    );
  }
  if (value.toLowerCase() === CONSENT_PHRASE) {
    return <>Almost — the phrase is all lower case.</>;
  }
  return (
    <>
      That is not the confirmation phrase. Type{" "}
      <code className="font-mono">{CONSENT_PHRASE}</code> exactly.
    </>
  );
}

export function RlsCheck({
  auditId,
  token,
  repoUrl,
}: {
  auditId: string;
  token: string | null;
  repoUrl: string | null;
}) {
  const [phrase, setPhrase] = useState("");
  const [anonKey, setAnonKey] = useState("");
  const [projectUrl, setProjectUrl] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RlsCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [metadata, setMetadata] = useState<RlsAccessReviewInput | null>(null);
  const [metadataValid, setMetadataValid] = useState(true);

  const publicKey = anonKey.trim();
  const project = projectUrl.trim();
  const publishable = publicKey.startsWith("sb_publishable_");
  const projectMatch = project.match(PROJECT_URL);
  const projectError = project && !projectMatch
    ? "Use your Supabase Project URL: https://<project-ref>.supabase.co, without a path or query."
    : publishable && !project
      ? "Enter the Project URL for this publishable key so we know which database to check."
      : null;
  const keyError = keyInputError(publicKey, projectMatch?.[1].toLowerCase());
  const canRun = !running && metadataValid && !projectError && !keyError && phrase.trim() === CONSENT_PHRASE;

  // The audit-scoped route re-reads the repository from its stored URL. An
  // audit created from a zip upload has none, and the backend refuses with a
  // reason — offering a button that can only be refused is worse than not
  // offering it.
  if (!repoUrl) return null;

  async function run() {
    if (!canRun) return;
    setRunning(true);
    setError(null);
    try {
      setResult(
        await runRlsCheck(auditId, {
          consent: phrase.trim(),
          token,
          anonKey: publicKey || undefined,
          projectUrl: project || undefined,
          accessReview: metadata,
        }),
      );
    } catch (e) {
      setError(
        e instanceof ApiError
          ? e.message
          : "the check could not be started",
      );
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="mt-8 rounded-xl border border-border p-5">
      <h2 className="text-lg font-semibold">Check it against your live database</h2>

      <p className="mt-2 text-sm text-muted">
        Everything above was read from your repository. Your repository and your
        deployment often differ — so this asks the database itself, using the
        public key your app already hands to every visitor.
      </p>
      <p className="mt-2 text-sm text-muted">
        It requests at most three rows per table, for up to 12 tables. The
        database requests stop after 45 seconds, and oversized responses are
        not evaluated. No value from those rows is stored or shown: the result
        records column names, a count, and lengths.
      </p>
      {/* Named explicitly because the first customer to see this block went
          looking for a field to paste their GitHub URL into. There is none —
          the repository comes from the audit — and saying which one is being
          read is a better answer than a field that should not exist. */}
      <p className="mt-2 text-sm text-muted">
        We work out which tables to ask about from{" "}
        <span className="font-mono text-xs">{repoUrl}</span>, the repository
        this audit ran on. Nothing to paste — we re-read it ourselves.
      </p>

      {!result && (
        <div className="mt-4 space-y-3">
          <RlsMetadataInput value={metadata} onChange={setMetadata} onValidity={setMetadataValid} disabled={running} />
          <label className="block text-sm">
            <span className="text-muted">
              Public key (optional for legacy anon keys in the repository)
            </span>
            <input
              type="text"
              value={anonKey}
              onChange={(e) => { setAnonKey(e.target.value); setPhrase(""); setError(null); }}
              disabled={running}
              aria-invalid={!!keyError}
              aria-describedby="rls-public-key-help"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="sb_publishable_… or eyJ…"
              className="mt-1 w-full rounded-md border border-border bg-transparent px-3 py-2 font-mono text-xs"
            />
          </label>
          <p id="rls-public-key-help" className="text-xs text-muted">
            Use a publishable key or a legacy anon key from your Supabase project&apos;s API Keys settings.
            {" "}Leave blank to look for a legacy anon key in your repository.
          </p>
          {keyError && <p role="alert" className="text-xs text-red-500">{keyError}</p>}
          <label className="block text-sm">
            <span className="text-muted">Project URL{publishable ? " (required)" : " (optional for legacy anon keys)"}</span>
            <input
              type="url"
              value={projectUrl}
              onChange={(e) => { setProjectUrl(e.target.value); setPhrase(""); setError(null); }}
              disabled={running}
              required={publishable}
              aria-invalid={!!projectError}
              aria-describedby="rls-project-url-help"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="https://your-project-ref.supabase.co"
              className="mt-1 w-full rounded-md border border-border bg-transparent px-3 py-2 font-mono text-xs"
            />
          </label>
          <p id="rls-project-url-help" className="text-xs text-muted">
            Copy the Project URL from Supabase&apos;s Connect dialog. Enter it together with your publishable key.
          </p>
          {projectError && <p role="alert" className="text-xs text-red-500">{projectError}</p>}

          {/* A BOX, NOT A THIRD FIELD. The same customer pasted their
              repository URL in here twice — the second time with the
              explanation from the last attempt sitting right there on screen,
              which is how we know the words were not the problem. Two
              identically styled inputs in a row make the second one read as
              "the other thing you have", and the other thing they had was the
              URL. So the confirmation stops looking like a form field and
              starts looking like a gate: its own frame, its own heading, and
              the phrase on a line of its own where it can be copied. */}
          <div className="rounded-lg border border-border bg-border/10 p-4">
            <p className="text-sm font-medium">Confirm this is your project</p>
            <p className="mt-1 text-xs text-muted">
              Type these words — not a URL, not your key. We ask for words
              rather than a checkbox because the next click sends requests to
              your live database.
            </p>
            <code className="mt-2 block select-all font-mono text-sm">
              {CONSENT_PHRASE}
            </code>
            <input
              type="text"
              value={phrase}
              onChange={(e) => setPhrase(e.target.value)}
              disabled={running}
              placeholder={CONSENT_PHRASE}
              // A phone keyboard capitalises the first letter and offers to
              // correct an unknown hyphenated word. Either turns the phrase
              // into something that looks right to the person who typed it
              // and does not match, which is the worst version of this bug:
              // the screen says "that is not the phrase" about text that
              // reads as the phrase.
              autoComplete="off"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              className="mt-2 w-full rounded-md border border-border bg-transparent px-3 py-2 font-mono text-sm"
            />
            {/* Directly under the input it belongs to. It used to sit below
                the button, two elements from the field the reader was looking
                at, which is a footnote rather than an answer. */}
            {!running && phrase.trim() !== CONSENT_PHRASE && (
              <p className="mt-2 text-xs text-muted">{unmetReason(phrase)}</p>
            )}
          </div>

          <button
            onClick={run}
            disabled={!canRun}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-black disabled:opacity-40"
          >
            {running ? <Spinner /> : "Run the check"}
          </button>
        </div>
      )}

      {error && <p className="mt-3 text-sm text-red-500">{error}</p>}

      {result && <Outcome result={result} />}
      {result && <button type="button" className="mt-3 text-xs underline" onClick={() => {
        setResult(null); setError(null); setPhrase("");
      }}>Prepare another check</button>}
    </div>
  );
}

function Outcome({ result }: { result: RlsCheckResult }) {
  if (result.status === "refused") {
    return (
      <div className="mt-4 rounded-md border border-border p-4 text-sm">
        <p className="font-medium">We did not check.</p>
        <p className="mt-1 text-muted">{result.reason}</p>
      </div>
    );
  }

  const exposed = result.exposed_tables;

  return (
    <div className="mt-4 space-y-4 text-sm">
      <div className="rounded-md border border-border p-4">
        <p className="font-medium">
          {exposed.length > 0
            ? `Anonymous requests read rows from ${exposed.length} ${exposed.length === 1 ? "table" : "tables"}.`
            : "No readable rows were confirmed."}
        </p>
        {exposed.length > 0 && (
          <p className="mt-1 text-muted">
            Anyone with your app&apos;s public key can make the same request.
            This may be intentional for public data, such as a catalog.
            Check whether these rows are meant to be public before treating
            this as a security issue.
          </p>
        )}
        {result.empty_but_unproven > 0 && (
          <p className="mt-1 text-muted">
            {result.empty_but_unproven} {result.empty_but_unproven === 1 ? "answer was" : "answers were"} empty.
            An empty answer does not prove protection. It can mean no rows,
            filtered rows, or a difference between this deployment and the
            data you expected. This check does not test access between users.
          </p>
        )}
        {result.inconclusive > 0 && (
          <p className="mt-1 text-muted">
            {result.inconclusive} {result.inconclusive === 1 ? "request was" : "requests were"} inconclusive.
            Errors do not establish whether those tables allow access.
          </p>
        )}
      </div>

      {result.attempts.length > 0 && (
        <ul className="space-y-2" aria-label="Table results">
          {result.attempts.map((attempt, index) => (
            <li key={index}>
              <span className="font-mono text-xs">
                {typeof attempt.evidence.table === "string" ? attempt.evidence.table : "Table"}
              </span>{" — "}
              {attemptSummary(attempt)}
            </li>
          ))}
        </ul>
      )}

      {result.access_review && <RlsMetadataOutcome review={result.access_review} />}

      <div className="text-muted">
        <p>
          We asked about {result.checked.length}{" "}
          {result.checked.length === 1 ? "table" : "tables"} named in your
          repository&apos;s migrations, generated types, or client calls.
          Tables absent from these sources are outside this check.
          Each result describes this request at the time it ran.
        </p>
        {result.not_checked.length > 0 && (
          <p className="mt-2">
            {result.not_checked.length} more were named but not asked about.
            {result.stop_reason === "time_budget_exceeded"
              ? " The time budget was exhausted. "
              : result.stop_reason === "table_limit"
                ? ` The table limit was reached (${result.max_tables}). `
                : " The check ended before these tables were requested. "}
            <span className="font-mono text-xs">
              {result.not_checked.join(", ")}
            </span>
          </p>
        )}
      </div>
    </div>
  );
}

function attemptSummary(attempt: RlsAttempt): string {
  // Render our vocabulary, never a database's free-form error message.
  switch (attempt.evidence.reason) {
    case "rows_readable":
      return "Rows readable anonymously; confirm whether public access is intended.";
    case "empty_result":
      return "Empty result; protection is unproven.";
    case "permission_denied":
      return "Database denied this request; this does not assess other roles or operations.";
    case "table_not_exposed":
      return "Table not found in the published API schema; check its name and deployment.";
    case "authentication_failed":
      return "Key or request authentication rejected; table access is undetermined.";
    case "rate_limited":
      return "Request rate limited; table access is undetermined.";
    case "server_error":
      return "Database service error; table access is undetermined.";
    case "request_timeout":
      return "Request timed out; table access is undetermined.";
    case "response_too_large":
      return "Response too large to evaluate; table access is undetermined.";
    case "unsupported_encoding":
      return "Response compression is unsupported; table access is undetermined.";
    case "invalid_response":
      return "Invalid response format; table access is undetermined.";
    default:
      return "No interpretable result; table access is undetermined.";
  }
}
