"use client";

import { useEffect, useId, useRef, useState } from "react";

export function CopyAuditLink() {
  const [state, setState] = useState<"idle" | "copying" | "copied" | "manual">("idle");
  const [manualLink, setManualLink] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const instructionsId = useId();

  useEffect(() => {
    if (state === "manual") {
      inputRef.current?.focus();
      inputRef.current?.select();
    }
  }, [state]);

  async function copyLink() {
    // Keep the complete access link as it was when clicked, even if polling
    // redirects to the finished report while the clipboard request is pending.
    const link = window.location.href;
    setState("copying");
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(link);
      setState("copied");
    } catch {
      setManualLink(link);
      setState("manual");
    }
  }

  return (
    <div className="mt-4">
      <button
        type="button"
        onClick={() => void copyLink()}
        disabled={state === "copying"}
        className="rounded-md border border-border px-3 py-2 text-sm font-medium hover:border-accent disabled:opacity-50"
      >
        {state === "copying" ? "Copying…" : "Copy audit link"}
      </button>
      <p role="status" className="mt-2 text-sm text-muted">
        {state === "copied" ? "Link copied. Open it later to see your result." : ""}
      </p>
      {state === "manual" && (
        <div className="mt-2">
          <p id={instructionsId} className="text-sm text-muted">
            Automatic copying is unavailable. Copy the selected link below.
          </p>
          <label htmlFor={inputId} className="mt-2 block text-sm font-medium">
            Audit link
          </label>
          <input
            ref={inputRef}
            id={inputId}
            type="text"
            readOnly
            value={manualLink}
            aria-describedby={instructionsId}
            onFocus={(event) => event.currentTarget.select()}
            className="mt-1 w-full rounded-md border border-border bg-surface px-3 py-2 text-sm"
          />
        </div>
      )}
    </div>
  );
}
