"use client";

// The boundary above our routes. Without it a single render error anywhere in
// a page blanks drydock.co entirely -- the exact finding this product ships
// (`missing-error-boundary`), which our own repository was failing until now.
//
// This renders INSIDE the root layout, so Tailwind, the fonts and Providers are
// already mounted and safe to use here. The one that cannot assume them is
// `global-error.tsx`, which replaces the layout; see the note there.
export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="mx-auto flex max-w-xl flex-col items-start gap-4 px-6 py-24">
      <h2 className="text-2xl font-semibold text-text">Something went wrong</h2>
      <p className="text-muted">
        An unexpected error occurred while loading this page. Trying again often
        works; if it does not, the reference below identifies this exact failure
        in our logs.
      </p>
      <button
        onClick={() => reset()}
        className="rounded-md bg-accent px-4 py-2 font-medium text-bg transition-opacity hover:opacity-90"
      >
        Try again
      </button>
      {/* The digest is Next's own correlation id for the server-side error. It
          is the only part of the failure a visitor can usefully hand us, and it
          reveals nothing about the fault itself. */}
      {error.digest ? (
        <p className="font-mono text-xs text-muted">
          Reference: {error.digest}
        </p>
      ) : null}
    </div>
  );
}
