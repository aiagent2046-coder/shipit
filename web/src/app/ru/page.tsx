import Link from "next/link";

import { CONVERSION_NOTE, FIXPACK_PRICE_USD } from "./price";

export const metadata = {
  title: "Drydock — аудит безопасности кода и Fix Pack",
  description:
    "Русскоязычная информация о Drydock: аудит безопасности кода, Fix Pack, стоимость, порядок оплаты и правовые документы.",
};

export default function RussianHomePage() {
  return (
    <div className="mx-auto max-w-5xl px-4 py-10">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">
            Drydock — аудит безопасности кода и Fix Pack
          </h1>
          <p className="mt-3 max-w-3xl text-muted">
            Drydock анализирует GitHub-репозитории, показывает потенциальные риски и, для поддерживаемых находок, может подготовить Fix Pack — отдельный pull request с исправлениями для вашего ревью.
          </p>
        </div>
        <Link href="/" className="text-sm text-accent underline underline-offset-2">
          English version
        </Link>
      </header>

      <section className="mt-10 grid gap-5 md:grid-cols-3">
        <div className="rounded-xl border border-border bg-elevated p-5">
          <h2 className="font-semibold">Бесплатный аудит</h2>
          <p className="mt-2 text-sm text-muted">
            Проверка репозитория на поддерживаемые проблемы без оплаты и без подписки.
          </p>
        </div>
        <div className="rounded-xl border border-accent/40 bg-accent/5 p-5">
          <h2 className="font-semibold">Fix Pack — ${FIXPACK_PRICE_USD}</h2>
          <p className="mt-2 text-sm text-muted">
            Разовая платная услуга для одного конкретного аудита. Никаких автоматических повторных списаний.
          </p>
        </div>
        <div className="rounded-xl border border-border bg-elevated p-5">
          <h2 className="font-semibold">GitHub pull request</h2>
          <p className="mt-2 text-sm text-muted">
            Исправления не мержатся автоматически. Вы получаете PR и сами принимаете решение после проверки diff и результатов верификации.
          </p>
        </div>
      </section>

      <section className="mt-10 rounded-xl border border-border bg-surface p-6">
        <h2 className="text-xl font-semibold">Стоимость и порядок оплаты</h2>
        <p className="mt-3 text-muted">
          Стоимость одного Fix Pack — <strong>${FIXPACK_PRICE_USD} USD</strong> за один аудит. Оплата разовая, без подписки и автоматических повторных списаний.
        </p>
        <p className="mt-3 text-muted">{CONVERSION_NOTE}</p>
        <p className="mt-3 text-muted">
          Оплата будет приниматься через платёжную систему Robokassa после завершения подключения магазина. До перехода к оплате покупателю показываются наименование услуги и итоговая сумма заказа.
        </p>
        <p className="mt-3 text-muted">
          После подтверждения оплаты Robokassa Drydock автоматически запускает оказание услуги. Результат предоставляется сразу после успешного выполнения Fix Pack, но не позднее <strong>24 часов с момента подтверждения платежа</strong>.
        </p>
        <a
          href="https://robokassa.com/"
          target="_blank"
          rel="noreferrer"
          className="mt-5 inline-flex items-center gap-4 rounded-lg border border-border bg-white px-4 py-3 text-sm text-black transition-colors hover:border-accent"
          aria-label="Оплата через Robokassa — официальный сайт платёжной системы"
        >
          <img
            src="/robokassa-badge.svg"
            alt="Robokassa"
            width="74"
            height="42"
            className="h-10 w-auto"
          />
          <span>Оплата через платёжную систему Robokassa</span>
        </a>
        <p className="mt-3 text-sm text-muted">
          Платёжные данные банковской карты вводятся на защищённой стороне Robokassa и её платёжных партнёров. Drydock не запрашивает полный номер карты, срок действия или CVC/CVV-код для платежа через Robokassa.
        </p>
        <p className="mt-3 text-sm text-muted">
          Подключение Robokassa ещё не завершено, поэтому активная кнопка оплаты появится только после получения и проверки рабочих параметров магазина.
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          <Link href="/ru/offer" className="rounded-lg border border-border px-4 py-2 text-sm font-medium hover:border-accent hover:text-accent">
            Публичная оферта
          </Link>
          <Link href="/ru/refund" className="rounded-lg border border-border px-4 py-2 text-sm font-medium hover:border-accent hover:text-accent">
            Условия возврата
          </Link>
        </div>
      </section>

      <section className="mt-10 rounded-xl border border-border bg-elevated p-6">
        <h2 className="text-xl font-semibold">Продавец и контакты</h2>
        <div className="mt-4 space-y-1 text-sm text-muted">
          <p><strong className="text-text">Индивидуальный предприниматель Морозевская Кристина Олеговна</strong></p>
          <p>ИНН: 672215400765</p>
          <p>ОГРНИП: 326670000033868</p>
          <p>Адрес: Смоленская область, Угранский район, село Угра, ул. Некрасова, дом 16</p>
          <p>Телефон: <a className="text-accent underline underline-offset-2" href="tel:+79998109500">+7 (999) 810-95-00</a></p>
          <p>Email: <a className="text-accent underline underline-offset-2" href="mailto:support@drydock.co">support@drydock.co</a></p>
        </div>
      </section>

      <nav className="mt-10 grid gap-3 sm:grid-cols-3">
        <Link href="/ru/offer" className="rounded-lg border border-border p-4 hover:border-accent">Публичная оферта</Link>
        <Link href="/ru/privacy" className="rounded-lg border border-border p-4 hover:border-accent">Политика обработки персональных данных</Link>
        <Link href="/ru/refund" className="rounded-lg border border-border p-4 hover:border-accent">Условия возврата денежных средств</Link>
      </nav>
    </div>
  );
}
