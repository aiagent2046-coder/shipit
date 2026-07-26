"use client";

import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import type { AuditJobState, AuditJobStatus } from "@/lib/types";
import { getAuditJob, ApiError } from "@/lib/api";
import { Spinner } from "@/components/Spinner";

// Faster than FixpackPurchase's 10s: a Fix Pack involves a human paying and
// then a PR being opened, while an audit is typically done inside two minutes,
// and the whole point of the queue cutover is that the wait feels tracked.
const POLL_MS = 3_000;

const TERMINAL: ReadonlySet<AuditJobState> = new Set<AuditJobState>([
  "succeeded",
  "failed",
  "timed_out",
  "cancelled",
  "dead_letter",
]);

// error_code is written for operators (it goes in the job row and the logs),
// so nothing here is shown to a user raw. Anything unmapped is deliberately
// generic: a code we did not anticipate is one we cannot explain honestly.
function humanError(code: string | null): string {
  switch (code) {
    case "unsupported_stack":
      return "We can only audit Next.js and FastAPI projects right now.";
    case "zip_bomb":
    case "too_large":
    case "bad_archive":
    case "not_a_zip":
    case "payload_missing":
      return "We couldn't read that archive. Try re-zipping the project and uploading again.";
    case "repo_not_found":
      return "That repository isn't reachable. It has to be a public GitHub repo.";
    case "github_error":
    case "github_unreachable":
      return "GitHub wouldn't give us the code. That's usually temporary — try again in a few minutes.";
    default:
      return "Something went wrong running this audit. Please try again.";
  }
}

function progressLabel(state: AuditJobState): string {
  switch (state) {
    case "running":
      return "Scanning your code…";
    case "claimed":
      return "Starting the scan…";
    default:
      return "Queued — waiting for a free worker…";
  }
}

export default function PendingAuditPage() {
  return (
    <Suspense fallback={<div className="mx-auto max-w-2xl px-4 py-10" />}>
      <PendingAuditPageInner />
    </Suspense>
  );
}

function PendingAuditPageInner() {
  const params = useParams<{ jobId: string }>();
  const jobId = params.jobId;
  const searchParams = useSearchParams();
  const token = searchParams.get("token");
  const router = useRouter();

  const [job, setJob] = useState<AuditJobStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const stop = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const s = await getAuditJob(jobId, token);
        if (cancelled) return;
        setJob(s);
        if (!TERMINAL.has(s.state)) return;
        stop();
        if (s.state === "succeeded" && s.audit_id) {
          // The finished audit has its own access token, handed over by the
          // poll endpoint precisely so this redirect can read the result.
          const q = s.audit_access_token
            ? `?token=${encodeURIComponent(s.audit_access_token)}`
            : "";
          router.replace(`/audit/${encodeURIComponent(s.audit_id)}${q}`);
          return;
        }
        setError(humanError(s.error_code));
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiError && e.status === 404) {
          // A 404 here is the ownership answer, not a blip: the link is
          // missing or using the wrong token, and polling cannot fix it.
          stop();
          setError(
            "We can't find this audit. The link may be incomplete — it needs the token it was created with.",
          );
        }
        /* anything else is transient; keep polling */
      }
    }

    void check();
    pollRef.current = setInterval(check, POLL_MS);
    return () => {
      cancelled = true;
      stop();
    };
  }, [jobId, token, router, stop]);

  return (
    <div className="mx-auto max-w-2xl px-4 py-10">
      <Link href="/" className="text-sm text-muted hover:text-text">
        ← New audit
      </Link>

      {error ? (
        <div className="mt-6 rounded-xl border border-critical/40 bg-critical/10 p-6">
          <h1 className="text-lg font-semibold text-critical">
            This audit didn&apos;t finish
          </h1>
          <p className="mt-2 text-sm text-muted">{error}</p>
          <Link
            href="/"
            className="mt-4 inline-block rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-fg"
          >
            Run a new audit
          </Link>
        </div>
      ) : (
        <div className="mt-6 rounded-xl border border-border bg-elevated p-6">
          <div className="flex items-center gap-2 font-medium">
            <Spinner /> {progressLabel(job?.state ?? "queued")}
          </div>
          <p className="mt-3 text-sm text-muted">
            Most audits finish in a couple of minutes. You can close this tab —
            the scan keeps running, and this link will show the result.
          </p>
          <p className="mt-3 font-mono text-xs text-muted">job {jobId}</p>
        </div>
      )}
    </div>
  );
}
