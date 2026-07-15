import Link from "next/link";
import { ThemeToggle } from "./ThemeToggle";
import { ApiKeyWidget } from "./ApiKeyWidget";

export function Header() {
  return (
    <header className="sticky top-0 z-10 border-b border-border bg-bg/80 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <span
            className="flex h-6 w-6 items-center justify-center rounded bg-accent font-mono text-sm font-bold text-accent-fg"
            aria-hidden="true"
          >
            {"›"}
          </span>
          ShipIt
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
