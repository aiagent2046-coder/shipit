import Link from "next/link";

import { FIXPACK_PRICE_RUB, PAYMENT_PROVIDER } from "./price";

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
          <h2 className="font-semibold">Fix Pack — {FIXPACK_PRICE_RUB} ₽</h2>
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
          Стоимость одного Fix Pack — <strong>{FIXPACK_PRICE_RUB} ₽</strong> за один аудит. Цена фиксированная: она не зависит от размера репозитория, от количества найденных проблем и от курса валют. Оплата разовая, без подписки и автоматических повторных списаний.
        </p>
        <p className="mt-3 text-muted">
          Аудит репозитория — бесплатный. Платным является только Fix Pack: подготовка pull request с исправлениями для одного конкретного аудита.
        </p>

        <h3 className="mt-6 font-semibold">Как оформить и оплатить заказ</h3>
        <ol className="mt-3 list-decimal space-y-2 pl-5 text-muted">
          <li>
            Запустите бесплатный аудит: укажите ссылку на публичный
            GitHub-репозиторий на{" "}
            <Link href="/" className="text-accent underline underline-offset-2">
              главной странице
            </Link>
            . Оплата на этом шаге не требуется.
          </li>
          <li>
            На странице готового аудита нажмите «Buy Fix Pack». Откроется форма
            заказа: наименование услуги, номер заказа и итоговая сумма —{" "}
            <strong>{FIXPACK_PRICE_RUB} ₽</strong>.
          </li>
          <li>
            Укажите имя и адрес электронной почты — они нужны, чтобы сопоставить
            поступивший платёж с вашим заказом и написать вам о его состоянии.
          </li>
          <li>
            Подтвердите заказ и оплатите его. Сумма к оплате показывается до
            подтверждения платежа и совпадает с ценой, указанной на этой
            странице.
          </li>
        </ol>
        <p className="mt-3 text-muted">
          Fix Pack привязан к конкретному аудиту, поэтому заказ оформляется на
          странице этого аудита, а не отдельной корзиной: услуга не существует
          в отрыве от репозитория, для которого она оказывается.
        </p>
        <p className="mt-3 text-muted">
          После подтверждения оплаты Drydock запускает оказание услуги. Результат
          предоставляется сразу после успешного выполнения Fix Pack, но не позднее{" "}
          <strong>24 часов с момента подтверждения платежа</strong>. О подтверждении
          оплаты и о возврате средств мы уведомляем покупателя по электронной почте.
        </p>
        <p className="mt-5 text-sm text-muted">
          Приём платежей осуществляется через платёжную систему {PAYMENT_PROVIDER}.
          Платёжные данные банковской карты вводятся на защищённой стороне
          {" "}{PAYMENT_PROVIDER} и её платёжных партнёров: Drydock не запрашивает и не
          хранит полный номер карты, срок действия и CVC/CVV-код.
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          <Link href="/" className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-fg hover:opacity-90">
            Запустить бесплатный аудит
          </Link>
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
          <p>Адрес: 214030, г. Смоленск, ул. Некрасова, д. 16</p>
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
