import Link from "next/link";

export function Footer() {
  return (
    <footer className="mt-16 border-t border-border">
      <div className="mx-auto flex max-w-5xl flex-col items-center justify-between gap-3 px-4 py-6 text-sm text-muted sm:flex-row">
        <span>© {new Date().getFullYear()} Drydock</span>
        <nav className="flex items-center gap-4">
          <Link href="/pricing" className="transition-colors hover:text-text">
            Pricing
          </Link>
          <Link href="/privacy" className="transition-colors hover:text-text">
            Privacy
          </Link>
          <Link href="/terms" className="transition-colors hover:text-text">
            Terms
          </Link>
        </nav>
      </div>
    </footer>
  );
}
