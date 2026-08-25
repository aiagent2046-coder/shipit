"use client";

import { Suspense, useEffect, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";
import Link from "next/link";
import type { AuditResult, Finding, Score } from "@/lib/types";
import { getAudit, reportUrl, ApiError } from "@/lib/api";
import { RESULT_PREFIX } from "@/components/AuditForm";
import { ScoreRing, CategoryBars } from "@/components/ScoreRing";
import { FindingsList, SeveritySummary } from "@/components/FindingsList";
import { Spinner } from "@/components/Spinner";
import { FixpackPurchase } from "@/components/FixpackPurchase";
import { RlsCheck } from "@/components/RlsCheck";

interface View {
  id: string;
  stack: string;
  fileCount: number | null;
  score: Score;
  findings: Finding[];
  repoUrl: string | null;
  /**
   * From the API's `fixpack_auto_fixable`. Undefined when the page renders
   * from the just-finished run held in sessionStorage, which doesn't carry
   * it -- the purchase block is then shown, and the sell endpoints answer 409
   * if there is genuinely nothing to fix. Hiding the block is the courtesy;
   * the refusal is the protection.
   */
  autoFixable?: boolean;
}

function fromResult(r: AuditResult): View {
  return {
    id: r.audit_id,
    stack: r.stack,
    fileCount: r.file_count,
    score: r.score,
    findings: r.findings ?? [],
    repoUrl: r.repo_url ?? null,
  };
}

// useSearchParams() must sit under a Suspense boundary or `next build` fails
// prerendering this route ("useSearchParams() should be wrapped in a suspense
// boundary"). The inner component holds all the logic; this wrapper supplies it.
export default function AuditPage() {
  return (
    <Suspense fallback={<div className="mx-auto max-w-4xl px-4 py-10" />}>
      <AuditPageInner />
    </Suspense>
  );
}

function AuditPageInner() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const searchParams = useSearchParams();
  const token = searchParams.get("token");
  // Set by the return URL ЮKassa sends the payer back to. A MARKER, NOT A
  // FACT: it arrives in the buyer's own browser and anybody can type it, so it
  // may change what this page says and never what it does. Hence the wording
  // below is conditional -- it has to stay true for someone who added the
  // parameter by hand.
  const returnedFromPayment = searchParams.get("paid") === "1";
  const [view, setView] = useState<View | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    // Prefer the inline result the form just produced (sessionStorage).
    try {
      const stashed = sessionStorage.getItem(`${RESULT_PREFIX}${id}`);
      if (stashed) {
        setView(fromResult(JSON.parse(stashed) as AuditResult));
        setLoading(false);
        return;
      }
    } catch {
      /* fall through to GET */
    }

    // Fallback (shared link / reload): fetch the persisted row. Retry a few
    // times in case persistence is eventually consistent.
    async function load() {
      setLoading(true);
      setError(null);
      for (let attempt = 0; attempt < 3 && !cancelled; attempt++) {
        try {
          const row = await getAudit(id, token);
          if (cancelled) return;
          if (!row.score_json) {
            setError("This audit has no complete score to display yet.");
            setLoading(false);
            return;
          }
          setView({
            id: row.id,
            stack: row.stack,
            fileCount: row.file_count,
            score: row.score_json,
            findings: row.findings_json ?? [],
            repoUrl: row.repo_url ?? null,
            autoFixable: row.fixpack_auto_fixable,
          });
          setLoading(false);
          return;
        } catch (e) {
          if (e instanceof ApiError && e.status === 404 && attempt < 2) {
            await new Promise((r) => setTimeout(r, 1500));
            continue;
          }
          if (cancelled) return;
          setError(
            e instanceof ApiError
              ? e.status === 404
                ? "No audit found for this link. It may not have been persisted (the backend needs DATABASE_URL configured), or the link is missing/using the wrong access token."
                : e.message
              : "Could not load this audit.",
          );
          setLoading(false);
          return;
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [id, token]);

  // Both tiers show a score. The free one used to show none, because the
  // number went UP when fewer checks ran -- audit ed402e63 scored 7.2 with the
  // auth and injection rubrics and 9.1 without them. Two engine changes
  // removed that: unexamined categories no longer vote on the mean, and one
  // confident critical caps it, which the free static rules can trigger alone.
  // Recomputed on that same audit today: 5.4 full, 6.1 static-only.
  //
  // `scored` now only decides how much scope the page has to declare. The
  // honesty requirement did not go away, it moved: CategoryBars renders an
  // unexamined category as "not checked" instead of a full green bar, which
  // is the specific lie that mattered (issue #181).
  //
  // BOTH free bases, not just static_only. "static+preview" was added later
  // as the second free depth and this predicate was never widened, so every
  // preview scan took the paid branch: audit 2b957672 published a 3.8 ring
  // and "Not production-ready yet" while /pricing sells the free tier as
  // "No readiness score out of 10" and the landing page says it gives none
  // "on purpose". The page was handing out the paid tier's own listed
  // differentiator, and contradicting the price list on the same site.
  //
  // Same rule and same spelling as app/report/html.py, which has excluded
  // both all along -- this is the surface that drifted, not that one.
  const scored =
    !view ||
    (view.score.basis !== "static_only" &&
      view.score.basis !== "static+preview");

  return (
    <div className="mx-auto max-w-4xl px-4 py-10">
      <Link href="/" className="text-sm text-muted hover:text-text">
        ← New audit
      </Link>

      {loading && <LoadingState />}

      {!loading && error && (
        <div className="mt-6 rounded-xl border border-critical/40 bg-critical/10 p-6">
          <h1 className="text-lg font-semibold text-critical">
            Couldn&apos;t load this audit
          </h1>
          <p className="mt-2 text-sm text-muted">{error}</p>
          <Link
            href="/"
            className="mt-4 inline-block rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-fg"
          >
            Run a new audit
          </Link>
        </div>
      )}

      {!loading && view && (
        <div className="mt-6">
          <div className="rounded-xl border border-border bg-elevated p-5 sm:p-6">
            <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
              <div>
                {/* No mark out of ten from a scan that cannot earn one.
                    The premise for showing it — that a static-only total
                    stays close to the full one — held on the audit it was
                    measured on and broke on the next: 9.9 static-only against
                    4.7 full, on a repository with an unauthenticated endpoint
                    running commands as root. Security is filled by both
                    tiers, so it reads a clean 10.0 when only regexes looked,
                    and carries the mean. The bars and the findings stay; the
                    verdict goes. */}
                {scored ? (
                  <ScoreRing total={view.score.total} />
                ) : (
                  <div>
                    <p className="text-3xl font-semibold">
                      {view.findings.length}
                      <span className="ml-2 text-sm font-normal text-muted">
                        {view.findings.length === 1 ? "finding" : "findings"}
                      </span>
                    </p>
                    <p className="mt-2 text-sm text-muted">
                      Free scan — no score out of 10, because it does not look
                      at enough to give one. What it checked is below.
                    </p>
                  </div>
                )}
              </div>
              <div className="text-sm text-muted">
                <p>
                  stack:{" "}
                  <span className="font-mono text-text">{view.stack}</span>
                </p>
                {view.fileCount != null && (
                  <p>
                    files scanned:{" "}
                    <span className="font-mono text-text">
                      {view.fileCount}
                    </span>
                  </p>
                )}
                {/* Was `scored && …`, which hid the basis on exactly the
                    audits where it is the caveat: a static-only scan showed
                    no basis line at all, while a full one advertised
                    "static+llm". Backwards. The scope of a score belongs
                    beside it whichever scope it had. */}
                {view.score.basis && (
                  <p>
                    basis:{" "}
                    <span className="font-mono text-text">
                      {view.score.basis}
                    </span>
                  </p>
                )}
                <div className="mt-2">
                  <SeveritySummary findings={view.findings} />
                </div>
              </div>
            </div>

            <div className="my-6 border-t border-border" />
            <CategoryBars
              categories={view.score.categories}
              gatedBy={view.score.gated_by}
              unexamined={view.score.unexamined}
              scored={scored}
              findings={view.findings}
            />
            {!scored && (
              <div className="mt-4 text-sm text-muted">
                {/* Basis-specific, because the two free depths stopped being
                    the same scan. A preview reaches a model; a static-only
                    result did not, either because the spend cap was hit or
                    because the provider failed. Printing the wider claim over
                    the narrower scan overstates the thinnest audit there is.
                    Same split, same wording as app/report/html.py. */}
                <p>
                  These are the checks that run for free: credentials committed
                  to the repository, a committed .env, a .gitignore that misses
                  secret files, no tests, no CI, no Dockerfile
                  {view.score.basis === "static+preview"
                    ? ", and then one quick security review over the code."
                    : "."}
                </p>
                {/* Row-level security moved OUT of this list when the static
                    detector shipped, and it has to be described accurately
                    rather than just deleted: what runs reads the committed
                    migrations, and a repository is not a deployment. The block
                    below is how that gets settled. */}
                <p className="mt-2">
                  Row-level security is read from your committed migrations —
                  what your repository says, not what your database does. The
                  two often differ, which is what the live check below is for.
                </p>
                <p className="mt-2">
                  Not checked here: whether your routes verify who is calling
                  them, whether passwords are hashed, and whether user input
                  reaches somewhere dangerous. Those are left out of the score
                  rather than counted as passing, so it cannot rise for a check
                  we skipped — but it cannot tell you they are fine either.
                </p>
              </div>
            )}

            <div className="mt-6 flex flex-wrap gap-3">
              <a
                href={reportUrl(view.id, token)}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-md border border-border px-4 py-2 text-sm font-medium hover:border-accent"
              >
                View full HTML report ↗
              </a>
            </div>
          </div>

          {returnedFromPayment && (
            <div className="mt-8 rounded-xl border border-accent/40 bg-accent/10 p-4">
              <p className="font-semibold text-accent">
                You&apos;ve come back from the payment page.
              </p>
              <p className="mt-1 text-sm text-muted">
                If the payment went through, your Fix Pack starts on its own —
                usually within a few seconds — and its progress appears below.
                You don&apos;t need to pay again or keep this tab open; we email
                you either way.
              </p>
            </div>
          )}

          <FixpackPurchase
            auditId={view.id}
            repoUrl={view.repoUrl}
            autoFixable={view.autoFixable}
            accessToken={token}
          />

          <RlsCheck auditId={view.id} token={token} repoUrl={view.repoUrl} />

          <div className="mt-8">
            <h2 className="mb-3 text-lg font-semibold">
              Findings ({view.findings.length})
            </h2>
            <FindingsList findings={view.findings} />
          </div>
        </div>
      )}
    </div>
  );
}

function LoadingState() {
  return (
    <div className="mt-6">
      <div className="flex items-center gap-2 text-sm text-muted">
        <Spinner /> Loading audit…
      </div>
      <div className="mt-4 space-y-4">
        <div className="skeleton h-32 rounded-xl" />
        <div className="skeleton h-24 rounded-xl" />
        <div className="skeleton h-24 rounded-xl" />
      </div>
    </div>
  );
}
