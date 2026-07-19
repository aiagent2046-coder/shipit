"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";

// Where FixpackPurchase stashed the audit page before sending the user to
// GitHub — kept in sync with INSTALL_RETURN_KEY there.
const INSTALL_RETURN_KEY = "drydock:github-install-return";

// GitHub's App Setup URL points here after an install. It sends back
// `installation_id` (the new installation) and echoes our `state`
// (owner/repo). We don't need to persist either — the per-repo lookup is
// dynamic — so this page is purely a friendly confirmation plus a way back
// into the interrupted Fix Pack flow.
export default function GithubInstalledPage() {
  return (
    <Suspense fallback={<div className="mx-auto max-w-xl px-4 py-16" />}>
      <GithubInstalledInner />
    </Suspense>
  );
}

function GithubInstalledInner() {
  const searchParams = useSearchParams();
  const state = searchParams.get("state"); // owner/repo, if we set it
  const [returnUrl, setReturnUrl] = useState<string | null>(null);

  useEffect(() => {
    try {
      setReturnUrl(sessionStorage.getItem(INSTALL_RETURN_KEY));
    } catch {
      /* sessionStorage unavailable — fall back to home */
    }
  }, []);

  return (
    <div className="mx-auto max-w-xl px-4 py-16">
      <div className="rounded-xl border border-accent/40 bg-accent/10 p-6 sm:p-8">
        <h1 className="text-xl font-semibold text-accent">
          GitHub App installed
        </h1>
        <p className="mt-3 text-sm text-muted">
          Thanks — the Drydock GitHub App is now installed
          {state ? (
            <>
              {" "}
              for{" "}
              <span className="font-mono text-text">{state}</span>
            </>
          ) : null}
          . You can head back and continue where you left off — buying a Fix
          Pack will now be able to open a real pull request against your
          repository.
        </p>

        <div className="mt-6 flex flex-wrap gap-3">
          {returnUrl ? (
            <a
              href={returnUrl}
              className="rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-accent-fg hover:opacity-90"
            >
              Continue to your audit
            </a>
          ) : (
            <Link
              href="/"
              className="rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-accent-fg hover:opacity-90"
            >
              Start an audit
            </Link>
          )}
          <Link
            href="/"
            className="rounded-lg border border-border px-4 py-2.5 text-sm font-medium hover:border-accent"
          >
            Home
          </Link>
        </div>
      </div>
    </div>
  );
}
