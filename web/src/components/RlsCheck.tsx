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
import type { RlsCheckResult } from "@/lib/types";
import { Spinner } from "./Spinner";

const CONSENT_PHRASE = "i-own-this-project";

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
  if (value.startsWith("ey") && value.length > 40) {
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
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RlsCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // The audit-scoped route re-reads the repository from its stored URL. An
  // audit created from a zip upload has none, and the backend refuses with a
  // reason — offering a button that can only be refused is worse than not
  // offering it.
  if (!repoUrl) return null;

  async function run() {
    setRunning(true);
    setError(null);
    try {
      setResult(
        await runRlsCheck(auditId, {
          consent: phrase.trim(),
          token,
          anonKey: anonKey.trim() || undefined,
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
        It sends a handful of read-only requests, one per table, and reads at
        most three rows from each. No value from those rows is stored or shown:
        the result records column names, a count, and lengths.
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
          <label className="block text-sm">
            <span className="text-muted">
              Your project&apos;s public key, if it is not in the repository
              (optional — never a service_role key, we refuse those)
            </span>
            <input
              type="text"
              value={anonKey}
              onChange={(e) => setAnonKey(e.target.value)}
              placeholder="eyJhbGciOi…"
              className="mt-1 w-full rounded-md border border-border bg-transparent px-3 py-2 font-mono text-xs"
            />
          </label>

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
            disabled={running || phrase.trim() !== CONSENT_PHRASE}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-black disabled:opacity-40"
          >
            {running ? <Spinner /> : "Run the check"}
          </button>
        </div>
      )}

      {error && <p className="mt-3 text-sm text-red-500">{error}</p>}

      {result && <Outcome result={result} />}
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
      {exposed.length > 0 ? (
        <div className="rounded-md border border-red-500/40 bg-red-500/5 p-4">
          <p className="font-medium text-red-500">
            {exposed.length === 1
              ? "One table handed rows to the public key."
              : `${exposed.length} tables handed rows to the public key.`}
          </p>
          <p className="mt-1 text-muted">
            Anyone who opens your site can make the same request.
          </p>
          <ul className="mt-2 list-inside list-disc font-mono text-xs">
            {exposed.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </div>
      ) : (
        <div className="rounded-md border border-border p-4">
          <p className="font-medium">No rows came back.</p>
          {/* NOT "your tables are protected". RLS filters rather than denying,
              so a protected table and an EMPTY table answer identically — and
              a new project's tables are empty all the time. The backend counts
              those answers for exactly this sentence. */}
          {result.empty_but_unproven > 0 && (
            <p className="mt-1 text-muted">
              {result.empty_but_unproven === result.checked.length
                ? "Every answer was empty"
                : `${result.empty_but_unproven} of those answers were empty`}
              , and an empty answer is not proof of protection: a table that is
              locked and a table that has no rows in it look exactly the same
              from outside. If you know these tables hold data, that is the
              difference — and it means they are protected.
            </p>
          )}
        </div>
      )}

      <div className="text-muted">
        {/* "the tables we could name from your repository", never "your
            tables". MEASURED: on the one project we ran this against, the only
            table ever found genuinely exposed appeared in neither the
            migrations nor the client code, so nothing could have named it. */}
        <p>
          We asked about {result.checked.length}{" "}
          {result.checked.length === 1 ? "table" : "tables"} we could name from
          your repository — from your migrations, and from the{" "}
          <code className="font-mono text-xs">supabase.from(&apos;…&apos;)</code>{" "}
          calls in your code. A table neither of those mentions is not in this
          list, and we cannot know it exists.
        </p>
        <p className="mt-1 font-mono text-xs">{result.checked.join(", ")}</p>

        {result.not_checked.length > 0 && (
          <p className="mt-2">
            {result.not_checked.length} more were named but not asked about —
            this check stops at {result.max_tables}:{" "}
            <span className="font-mono text-xs">
              {result.not_checked.join(", ")}
            </span>
          </p>
        )}

        {result.inconclusive > 0 && (
          <p className="mt-2">
            {result.inconclusive}{" "}
            {result.inconclusive === 1 ? "request" : "requests"} settled
            nothing — the database did not answer in a way we can read.
          </p>
        )}
      </div>
    </div>
  );
}
