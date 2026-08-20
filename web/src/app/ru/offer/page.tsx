import Link from "next/link";

import { CONVERSION_NOTE, FIXPACK_PRICE_USD, REFUND_DAYS } from "../price";

export const metadata = {
  title: "Публичная оферта — Drydock",
  description: "Публичная оферта ИП Морозевской Кристины Олеговны на оказание цифровых услуг Drydock.",
};

export default function OfferPage() {
  return (
    <article className="mx-auto max-w-3xl px-4 py-10 leading-7">
      <Link href="/ru" className="text-sm text-muted hover:text-text">← На русскую страницу Drydock</Link>
      <h1 className="mt-6 text-3xl font-semibold tracking-tight">Публичная оферта</h1>
      <p className="mt-3 text-sm text-muted">Редакция от 20 августа 2026 года.</p>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">1. Общие положения</h2>
        <p className="mt-3">Настоящий документ является публичным предложением индивидуального предпринимателя Морозевской Кристины Олеговны (далее — «Исполнитель») заключить договор на оказание цифровых услуг Drydock на изложенных ниже условиях.</p>
        <p className="mt-3">Акцептом оферты является совершение Заказчиком оплаты выбранной услуги после ознакомления с её описанием, стоимостью, условиями оказания, настоящей офертой, политикой обработки персональных данных и условиями возврата денежных средств.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">2. Сведения об Исполнителе</h2>
        <ul className="mt-3 list-disc space-y-1 pl-6">
          <li>ИП Морозевская Кристина Олеговна</li>
          <li>ИНН: 672215400765</li>
          <li>ОГРНИП: 326670000033868</li>
          <li>Адрес: Смоленская область, Угранский район, село Угра, ул. Некрасова, дом 16</li>
          <li>Телефон: +7 (999) 810-95-00</li>
          <li>Email: support@drydock.co</li>
        </ul>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">3. Предмет договора</h2>
        <p className="mt-3">Drydock — программный сервис анализа исходного кода и подготовки результатов аудита. Платная услуга Fix Pack предоставляется для конкретного аудита и, при наличии поддерживаемых для автоматического исправления находок и технической возможности, формирует отдельный GitHub pull request с изменениями для самостоятельного просмотра и принятия Заказчиком.</p>
        <p className="mt-3">Исполнитель не выполняет автоматический merge изменений в репозиторий Заказчика. Результаты анализа и предложенные исправления не являются сертификацией безопасности и должны быть проверены Заказчиком до использования в production.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">4. Стоимость и оплата</h2>
        <p className="mt-3">Стоимость Fix Pack составляет <strong>${FIXPACK_PRICE_USD} USD за один Fix Pack</strong>. Услуга оплачивается один раз и не является подпиской. Автоматические повторные списания не производятся.</p>
        <p className="mt-3">{CONVERSION_NOTE}</p>
        <p className="mt-3">Оплата через Robokassa становится доступна после подключения магазина к платёжной системе. До перехода к оплате Заказчик видит на сайте наименование услуги и итоговую сумму заказа.</p>
        <p className="mt-3">Условия оплаты через Robokassa и ссылка на официальный сайт платёжной системы размещены на русскоязычной странице Drydock до момента перехода к оплате.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">5. Порядок и срок оказания услуги</h2>
        <ol className="mt-3 list-decimal space-y-2 pl-6">
          <li>Заказчик запускает аудит поддерживаемого GitHub-репозитория.</li>
          <li>Для Fix Pack должен существовать хотя бы один результат, поддерживаемый текущим механизмом автоматического исправления, а Drydock GitHub App должен иметь необходимые права на репозиторий.</li>
          <li>После получения подтверждения об оплате от Robokassa Drydock автоматически запускает задачу Fix Pack.</li>
          <li>При успешном выполнении Заказчику предоставляется ссылка на созданный GitHub pull request.</li>
        </ol>
        <p className="mt-3"><strong>Срок оказания услуги:</strong> результат предоставляется сразу после успешного автоматического выполнения Fix Pack, но не позднее 24 часов с момента подтверждения платежа.</p>
        <p className="mt-3">При технической невозможности оказать оплаченную услугу в указанном порядке применяется порядок возврата, опубликованный на странице «Условия возврата денежных средств».</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">6. Права и обязанности Заказчика</h2>
        <p className="mt-3">Заказчик подтверждает наличие законных прав на передачу выбранного репозитория или исходного кода для анализа. Заказчик обязан самостоятельно проверить предложенный pull request и несёт ответственность за решение о его принятии и использовании.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">7. Возвраты и претензии</h2>
        <p className="mt-3">Порядок отказа от услуги и возврата денежных средств опубликован по адресу <Link className="text-accent underline underline-offset-2" href="/ru/refund">/ru/refund</Link>. Для обращения укажите идентификатор заказа, дату и сумму оплаты и направьте запрос на support@drydock.co.</p>
        <p className="mt-3">Если оплата принята, а услуга не оказана — в том числе если для данного аудита автоматическое исправление оказалось невозможным, — Исполнитель рассматривает обращение и направляет возврат в платёжную систему в течение <strong>{REFUND_DAYS}</strong> с даты обращения.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">8. Персональные данные</h2>
        <p className="mt-3">Обработка персональных данных осуществляется в соответствии с опубликованной <Link className="text-accent underline underline-offset-2" href="/ru/privacy">Политикой обработки персональных данных</Link>.</p>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">9. Контакты</h2>
        <p className="mt-3">По вопросам заказа, исполнения договора и возврата средств: <a className="text-accent underline underline-offset-2" href="mailto:support@drydock.co">support@drydock.co</a>, телефон +7 (999) 810-95-00.</p>
      </section>
    </article>
  );
}
