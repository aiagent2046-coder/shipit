"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import type { AuditResult, Finding, Score } from "@/lib/types";
import { getAudit, reportUrl, ApiError } from "@/lib/api";
import { RESULT_PREFIX } from "@/components/AuditForm";
import { ScoreRing, CategoryBars } from "@/components/ScoreRing";
import { FindingsList, SeveritySummary } from "@/components/FindingsList";
import { Spinner } from "@/components/Spinner";

interface View {
  id: string;
  stack: string;
  fileCount: number | null;
  score: Score;
  findings: Finding[];
}

function fromResult(r: AuditResult): View {
  return {
    id: r.audit_id,
    stack: r.stack,
    fileCount: r.file_count,
    score: r.score,
    findings: r.findings ?? [],
  };
}

export default function AuditPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
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
          const row = await getAudit(id);
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
                ? "No audit found with this id. It may not have been persisted (the backend needs DATABASE_URL configured), or the link is wrong."
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
  }, [id]);

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
              <ScoreRing total={view.score.total} />
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
            <CategoryBars categories={view.score.categories} />

            <div className="mt-6 flex flex-wrap gap-3">
              <a
                href={reportUrl(view.id)}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-md border border-border px-4 py-2 text-sm font-medium hover:border-accent"
              >
                View full HTML report ↗
              </a>
              <Link
                href="/pricing"
                className="rounded-md bg-accent px-4 py-2 text-sm font-semibold text-accent-fg hover:opacity-90"
              >
                Get a Fix Pack for these issues →
              </Link>
            </div>
          </div>

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
