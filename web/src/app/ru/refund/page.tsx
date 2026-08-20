import Link from "next/link";

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
        <p className="mt-3">Возврат производится, в частности, если Drydock подтвердил оплату, но не смог сформировать и предоставить Fix Pack в заявленном поддерживаемом сценарии в течение установленного срока из-за ошибки или недоступности своей инфраструктуры.</p>
        <p className="mt-3">Возврат не означает, что любой результат аудита гарантированно должен содержать исправляемую находку: до оформления Fix Pack сервис может отказать в продаже, если для данного аудита нет поддерживаемого исправления.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">4. Способ и срок возврата</h2>
        <p className="mt-3">Одобренный возврат выполняется тем способом, который поддерживается платёжной системой для исходной операции. Фактический срок зачисления зависит от Robokassa, банка и использованного платёжного метода.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">5. Контакты продавца</h2>
        <p className="mt-3">ИП Морозевская Кристина Олеговна, ИНН 672215400765, ОГРНИП 326670000033868. Адрес: Смоленская область, Угранский район, село Угра, ул. Некрасова, дом 16. Телефон: +7 (999) 810-95-00. Email: support@drydock.co.</p>
      </section>
    </article>
  );
}
