import Link from "next/link";
import { ThemeToggle } from "./ThemeToggle";
import { ApiKeyWidget } from "./ApiKeyWidget";

export function Header() {
  return (
    <header className="sticky top-0 z-10 border-b border-border bg-bg/80 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <span
            className="flex h-6 w-6 items-center justify-center rounded bg-accent text-accent-fg"
            aria-hidden="true"
          >
            <svg
              viewBox="0 0 24 24"
              className="h-4 w-4"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.6}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {/* Graving-dock cross-section: a basin (U) cradling a hull
                  raised on keel blocks — a ship in dry dock. */}
              <path d="M3 5v13h18V5" />
              <path d="M6.5 8h11l-2.2 5h-6.6z" />
              <path d="M10 13v5M14 13v5" />
            </svg>
          </span>
          Drydock
        </Link>
        <nav className="flex items-center gap-2 sm:gap-3">
          <Link
            href="/pricing"
            className="rounded-md px-3 py-1.5 text-sm text-muted transition-colors hover:text-text"
          >
            Pricing
          </Link>
          <ApiKeyWidget />
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
}
