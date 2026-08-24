import Link from "next/link";

import { PAYMENT_PROVIDER } from "@/app/ru/price";

const SUPPORT_EMAILS: { address: string; label: string }[] = [
  { address: "support@drydock.co", label: "technical support, orders, refunds" },
  { address: "info@drydock.co", label: "advertising and partnerships" },
  { address: "email@drydock.co", label: "the developer, directly" },
];
const SUPPORT_TELEGRAM = "drydocksupport_bot";

export function Footer() {
  return (
    <footer className="mt-16 border-t border-border">
      <div className="mx-auto max-w-5xl px-4 py-8 text-sm text-muted">
        <div className="grid gap-8 md:grid-cols-3">
          <section>
            <h2 className="font-medium text-text">Contact</h2>
            <ul className="mt-2 space-y-1">
              {SUPPORT_EMAILS.map(({ address, label }) => (
                <li key={address}>
                  <a href={`mailto:${address}`} className="transition-colors hover:text-text">
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
                <span className="block text-xs opacity-70">
                  collecting or recovering a purchased key
                </span>
              </li>
            </ul>
          </section>

          <section>
            <h2 className="font-medium text-text">Правовая информация</h2>
            <ul className="mt-2 space-y-1">
              <li><Link href="/ru" className="transition-colors hover:text-text">Информация для покупателей РФ</Link></li>
              <li><Link href="/ru/offer" className="transition-colors hover:text-text">Публичная оферта</Link></li>
              <li><Link href="/ru/privacy" className="transition-colors hover:text-text">Политика обработки персональных данных</Link></li>
              <li><Link href="/ru/refund" className="transition-colors hover:text-text">Условия возврата денежных средств</Link></li>
              {/* Named from the same constant the offer, the refund terms and
                  the privacy policy read, so the footer cannot go on
                  advertising last month's payment system after the documents
                  have moved on. It did: the site carried a Robokassa badge
                  while an application to ЮMoney was under review, which is
                  what a ЮMoney reviewer saw when they opened the offer.

                  Text, not a logo. Using a payment system's mark is a
                  permission granted with a live merchant account, and we do
                  not have one yet -- a badge for a system that has not
                  approved us claims a relationship that does not exist. */}
              <li>Приём платежей: {PAYMENT_PROVIDER}</li>
            </ul>
          </section>

          <section>
            <h2 className="font-medium text-text">Продавец в РФ</h2>
            <div className="mt-2 space-y-1">
              <p className="text-text">ИП Морозевская Кристина Олеговна</p>
              <p>ИНН: 672215400765</p>
              <p>ОГРНИП: 326670000033868</p>
              <p>Адрес: Смоленская область, Угранский район, село Угра, ул. Некрасова, дом 16</p>
              <p>
                Телефон:{" "}
                <a href="tel:+79998109500" className="transition-colors hover:text-text">
                  +7 (999) 810-95-00
                </a>
              </p>
              <p>
                Email:{" "}
                <a href="mailto:support@drydock.co" className="transition-colors hover:text-text">
                  support@drydock.co
                </a>
              </p>
            </div>
          </section>
        </div>

        <div className="mt-8 flex flex-col items-center justify-between gap-3 border-t border-border pt-6 sm:flex-row">
          <span>© {new Date().getFullYear()} Drydock</span>
          <nav className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2">
            <Link href="/pricing" className="transition-colors hover:text-text">Pricing</Link>
            <Link href="/payment-details" className="transition-colors hover:text-text">Payment details</Link>
            <Link href="/privacy" className="transition-colors hover:text-text">Privacy</Link>
            <Link href="/terms" className="transition-colors hover:text-text">Terms</Link>
            <Link href="/ru" className="transition-colors hover:text-text">RU</Link>
            <a
              href="https://github.com/aiagent2046-coder/shipit"
              target="_blank"
              rel="noreferrer"
              className="transition-colors hover:text-text"
            >
              Source code (AGPL-3.0)
            </a>
          </nav>
        </div>
      </div>
    </footer>
  );
}
