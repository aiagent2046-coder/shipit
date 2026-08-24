import Link from "next/link";

import { PAYMENT_PROVIDER, REFUND_DAYS } from "../price";

export const metadata = {
  title: "Условия возврата денежных средств — Drydock",
  description: "Порядок отказа от услуги и возврата денежных средств за Fix Pack Drydock.",
};

export default function RefundPage() {
  return (
    <article className="mx-auto max-w-3xl px-4 py-10 leading-7">
      <Link href="/ru" className="text-sm text-muted hover:text-text">← На русскую страницу Drydock</Link>
      <h1 className="mt-6 text-3xl font-semibold tracking-tight">Условия возврата денежных средств</h1>
      <p className="mt-3 text-sm text-muted">Редакция от 20 августа 2026 года.</p>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">1. Общий порядок</h2>
        <p className="mt-3">Fix Pack является цифровой услугой, оказываемой для конкретного аудита и репозитория. После подтверждения платежа услуга запускается автоматически и должна быть предоставлена сразу после успешного выполнения Fix Pack, но не позднее 24 часов с момента подтверждения платежа.</p>
        <p className="mt-3">Если оплаченная услуга не была оказана по техническим причинам Drydock и пользователь не получил заявленный результат, пользователь вправе обратиться за возвратом денежных средств.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">2. Как подать заявку</h2>
        <p className="mt-3">Направьте письмо на <a className="text-accent underline underline-offset-2" href="mailto:support@drydock.co">support@drydock.co</a> в течение 14 календарных дней с даты оплаты. Укажите:</p>
        <ul className="mt-3 list-disc space-y-2 pl-6">
          <li>номер или иной идентификатор заказа;</li>
          <li>дату и сумму оплаты;</li>
          <li>адрес электронной почты, использованный при оформлении;</li>
          <li>краткое описание причины обращения.</li>
        </ul>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">3. Когда производится возврат</h2>
        <p className="mt-3">Возврат производится, если Drydock подтвердил оплату, но не предоставил Заказчику результат услуги. Это относится, в частности, к следующим случаям:</p>
        <ul className="mt-3 list-disc space-y-2 pl-6">
          <li>Fix Pack не был сформирован и предоставлен в течение установленного срока из-за ошибки или недоступности инфраструктуры Drydock;</li>
          {/* The case that actually happened and that the previous wording did
              not cover: audit bd970b2b was sold a Fix Pack and got "Nothing to
              auto-fix". The infrastructure worked perfectly — we sold
              something we could not do. Наличие или отсутствие сбоя не должно
              решать, вернутся ли деньги человеку, который ничего не получил. */}
          <li><strong>оплата была принята, а автоматическое исправление для данного аудита оказалось невозможным</strong>, и Заказчик не получил pull request с изменениями;</li>
          <li>pull request не был создан по причинам, зависящим от Drydock.</li>
        </ul>
        <p className="mt-3">Сервис стремится определить отсутствие поддерживаемого исправления до оплаты и в этом случае не предлагает покупку Fix Pack. Если такая проверка не сработала и оплата была принята, применяется предыдущий абзац: услуга считается неоказанной, и уплаченная сумма возвращается.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">4. Способ и срок возврата</h2>
        <p className="mt-3">Drydock рассматривает обращение и, если возврат одобрен, направляет распоряжение о возврате в платёжную систему в течение <strong>{REFUND_DAYS}</strong> с даты получения обращения.</p>
        <p className="mt-3">Возврат выполняется тем способом, который поддерживается платёжной системой для исходной операции. Срок зачисления средств на счёт Заказчика после направления распоряжения зависит от {PAYMENT_PROVIDER}, банка-эмитента и использованного платёжного метода и находится вне контроля Drydock.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">5. Контакты продавца</h2>
        <p className="mt-3">ИП Морозевская Кристина Олеговна, ИНН 672215400765, ОГРНИП 326670000033868. Адрес: 214030, г. Смоленск, ул. Некрасова, д. 16. Телефон: +7 (999) 810-95-00. Email: support@drydock.co.</p>
      </section>
    </article>
  );
}
