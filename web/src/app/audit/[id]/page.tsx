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

  // A static-only audit shows no readiness score, and the reason is the point:
  // the number goes UP when fewer checks run, because the findings that would
  // lower it were never looked for. Measured on audit ed402e63 -- 7.2 with the
  // auth and injection rubrics, 9.1 without them, and Auth reading 10.0 for a
  // repository whose subscriptions table has no write RLS policies. That is the
  // defect from issue #181 (a category scoring ten because nothing looked at
  // it), and showing it to a free visitor would be reassurance pointing the
  // wrong way -- on the page whose headline question is whether this is safe to
  // ship. An audit with no basis at all predates the field and keeps its score.
  const scored = !view || view.score.basis !== "static_only";

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
              {scored ? (
                <ScoreRing total={view.score.total} />
              ) : (
                <div>
                  <p className="text-sm text-muted">Static scan</p>
                  <p className="text-lg font-semibold">
                    {view.findings.length === 0
                      ? "Nothing found by these checks"
                      : `${view.findings.length} issue${
                          view.findings.length === 1 ? "" : "s"
                        } found`}
                  </p>
                </div>
              )}
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
                {scored && view.score.basis && (
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
            {scored ? (
              <CategoryBars categories={view.score.categories} />
            ) : (
              <div className="text-sm text-muted">
                <p>
                  These are the checks that run for free: credentials committed
                  to the repository, a committed .env, a .gitignore that misses
                  secret files, no tests, no CI, no Dockerfile.
                </p>
                <p className="mt-2">
                  Not checked here: whether your routes verify who is calling
                  them, whether passwords are hashed, whether row-level security
                  is on, and whether user input reaches somewhere dangerous. So
                  there is no readiness score on this page — a score computed
                  from half the checks rises as fewer things are examined, which
                  would tell you the opposite of the truth.
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

          <FixpackPurchase
            auditId={view.id}
            repoUrl={view.repoUrl}
            autoFixable={view.autoFixable}
          />

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
