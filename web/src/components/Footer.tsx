import Link from "next/link";

// Support contacts. Static on purpose: unlike the bank requisites these are
// brand addresses that change with the brand, not with the operator's banking,
// so a rebuild is the right cost for changing them.
// Labelled, because three near-identical addresses with no stated difference
// read as sloppiness on a page where a stranger is deciding whether to trust
// us with money. support@ is the one the rest of the product points at.
const SUPPORT_EMAILS: { address: string; label: string }[] = [
  { address: "support@drydock.co", label: "technical support, orders, refunds" },
  { address: "info@drydock.co", label: "advertising and partnerships" },
  { address: "email@drydock.co", label: "the developer, directly" },
];
const SUPPORT_TELEGRAM = "drydocksupport_bot";

/**
 * Site footer: support contacts, and a link to the payment requisites rather
 * than the requisites themselves.
 *
 * The details used to render here directly. They are a private individual's
 * real banking data, and carrying them on every page put them in front of
 * every crawler and archiver on the web for the sake of the rare payer whose
 * bank asks for SWIFT/IBAN. /payment-details serves that payer just as well
 * and carries noindex.
 *
 * That split is also why this is a server component again: with no fetch left
 * there is no reason to ship it to the browser or to hit the API on every page
 * view.
 */
export function Footer() {
  return (
    <footer className="mt-16 border-t border-border">
      <div className="mx-auto max-w-5xl px-4 py-8 text-sm text-muted">
        <section>
          <h2 className="font-medium text-text">Contact</h2>
          <ul className="mt-2 space-y-1">
            {SUPPORT_EMAILS.map(({ address, label }) => (
              <li key={address}>
                <a
                  href={`mailto:${address}`}
                  className="transition-colors hover:text-text"
                >
                  {address}
                </a>
                <span className="block text-xs opacity-70">{label}</span>
              </li>
            ))}
            <li>
              <a
                href={`https://t.me/${SUPPORT_TELEGRAM}`}
                target="_blank"
                rel="noreferrer"
                className="transition-colors hover:text-text"
              >
                @{SUPPORT_TELEGRAM}
              </a>
              {/* Labelled like the addresses above it: the bot was the one
                  channel with no stated purpose, so a visitor could not tell
                  whether it was support, sales, or something else. */}
              <span className="block text-xs opacity-70">
                collecting or recovering a purchased key
              </span>
            </li>
          </ul>
        </section>

        <div className="mt-8 flex flex-col items-center justify-between gap-3 border-t border-border pt-6 sm:flex-row">
          <span>© {new Date().getFullYear()} Drydock</span>
          <nav className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2">
            <Link href="/pricing" className="transition-colors hover:text-text">
              Pricing
            </Link>
            <Link
              href="/payment-details"
              className="transition-colors hover:text-text"
            >
              Payment details
            </Link>
            <Link href="/privacy" className="transition-colors hover:text-text">
              Privacy
            </Link>
            <Link href="/terms" className="transition-colors hover:text-text">
              Terms
            </Link>
          </nav>
        </div>
      </div>
    </footer>
  );
}
