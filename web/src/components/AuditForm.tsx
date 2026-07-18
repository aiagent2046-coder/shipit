"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { createAudit, ApiError } from "@/lib/api";
import { useApiKey } from "./providers";
import { Spinner } from "./Spinner";

type Mode = "url" | "file";

// sessionStorage handoff: the POST completes inline (can take up to ~2 min)
// and returns the full result, so we stash it for the results page to show
// immediately instead of re-fetching. Exported so the results page reads
// the same key.
export const RESULT_PREFIX = "shipit-audit-";

export function AuditForm() {
  const router = useRouter();
  const { apiKey } = useApiKey();
  const [mode, setMode] = useState<Mode>("url");
  const [repoUrl, setRepoUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (mode === "url" && !repoUrl.trim()) {
      setError("Enter a public GitHub repo URL.");
      return;
    }
    if (mode === "file" && !file) {
      setError("Choose a .zip of your project.");
      return;
    }
    setSubmitting(true);
    try {
      const result = await createAudit(
        mode === "url" ? { repoUrl: repoUrl.trim() } : { file: file! },
        apiKey,
      );
      try {
        sessionStorage.setItem(
          `${RESULT_PREFIX}${result.audit_id}`,
          JSON.stringify(result),
        );
      } catch {
        /* sessionStorage may be unavailable; results page falls back to GET */
      }
      // Carry the ownership token in the URL so the results page (and any
      // link the user copies) can read the audit — it's 404 without it.
      const tokenQuery = result.access_token
        ? `?token=${encodeURIComponent(result.access_token)}`
        : "";
      router.push(
        `/audit/${encodeURIComponent(result.audit_id)}${tokenQuery}`,
      );
    } catch (e) {
      const msg =
        e instanceof ApiError
          ? e.message
          : "Something went wrong submitting the audit.";
      setError(msg);
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={submit}
      className="w-full rounded-xl border border-border bg-elevated p-4 shadow-lg sm:p-5"
    >
      <div
        className="mb-3 flex gap-1 rounded-lg border border-border bg-surface p-1 text-sm"
        role="tablist"
        aria-label="Audit input method"
      >
        {(["url", "file"] as Mode[]).map((m) => (
          <button
            key={m}
            type="button"
            role="tab"
            aria-selected={mode === m}
            onClick={() => {
              setMode(m);
              setError(null);
            }}
            className={`flex-1 rounded-md px-3 py-1.5 font-medium transition-colors ${
              mode === m
                ? "bg-bg text-text shadow-sm"
                : "text-muted hover:text-text"
            }`}
          >
            {m === "url" ? "GitHub URL" : "Upload .zip"}
          </button>
        ))}
      </div>

      {mode === "url" ? (
        <input
          type="url"
          inputMode="url"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          disabled={submitting}
          aria-label="Public GitHub repository URL"
          className="w-full rounded-lg border border-border bg-surface px-4 py-3 font-mono text-sm outline-none focus:border-accent disabled:opacity-60"
        />
      ) : (
        <div>
          <input
            ref={fileRef}
            type="file"
            accept=".zip,application/zip"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            disabled={submitting}
            aria-label="Project zip file"
            className="block w-full cursor-pointer rounded-lg border border-border bg-surface px-4 py-3 text-sm file:mr-3 file:rounded-md file:border-0 file:bg-accent file:px-3 file:py-1.5 file:text-accent-fg outline-none focus:border-accent disabled:opacity-60"
          />
          {file && (
            <p className="mt-1 font-mono text-xs text-muted">
              {file.name} ({Math.round(file.size / 1024)} KB)
            </p>
          )}
        </div>
      )}

      {error && (
        <p className="mt-3 text-sm text-critical" role="alert">
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={submitting}
        className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-3 font-semibold text-accent-fg transition-opacity hover:opacity-90 disabled:opacity-70"
      >
        {submitting ? (
          <>
            <Spinner /> Auditing… this can take up to ~2 minutes
          </>
        ) : (
          "Audit my app"
        )}
      </button>
      <p className="mt-2 text-center text-xs text-muted">
        Public GitHub repos only. The scan runs synchronously — keep this tab
        open until it finishes.
      </p>
    </form>
  );
}
