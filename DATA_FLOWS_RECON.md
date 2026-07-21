# DATA_FLOWS_RECON.md

Разведка потоков данных продукта **Drydock** (в коде исторически `shipit`) для
написания Privacy Policy / Terms of Service. Только факты, проверенные по коду,
со ссылками на файлы и строки. Юридических выводов нет.

Дата разведки: 2026-07-21. Ветка: `recon/data-flows`. Коммит только этого файла.

> Терминология: продукт называется **Drydock** во фронтенде и в маркетинге
> (`web/src/components/FixpackPurchase.tsx:23` — ключ `drydock:...`), но
> кодовая база, systemd-юниты, Supabase-проект и таблицы называются `shipit`.
> Это один и тот же продукт.

---

## 1. Какие персональные/пользовательские данные хранятся и где

Все таблицы — Postgres (Supabase). Определения в `migrations/0001`–`0018`.
На всех таблицах включён **RLS в режиме default-deny без policy** (миграции
0002, 0003, 0014, 0015, 0017): через анонимный/publishable-ключ PostgREST
строки недоступны. Само приложение подключается ролью-владельцем `postgres`
через Supavisor pooler, на владельца RLS не действует (комментарий в
`migrations/0002_enable_rls_default_deny.sql:58-63`).

### `audits` (`migrations/0001`, расширена 0006/0008/0010/0013)
Колонки: `id`, `stack`, `status`, `file_count`, `score_total`, `score_json`,
`findings_json`, `created_at`, `repo_url` (0006), `content_hash` (0008),
`access_token` (0010), `engine_version` (0013).
- **Идентифицирующее человека:**
  - `repo_url` — публичный URL GitHub-репозитория (`github.com/<owner>/<repo>`),
    сохраняется только при intake по URL, `NULL` для zip-загрузок
    (`migrations/0006_audits_repo_url.sql`, пишется в
    `app/main.py:1939` из `source_url`). Через `owner` косвенно указывает на
    владельца кода/аккаунт GitHub.
  - `findings_json` — результаты анализа (см. §2 ниже, что именно там лежит).
    Содержит **пути файлов** и **номера строк** из репозитория пользователя,
    тексты объяснений от LLM, и для секретов — **маскированный превью** (первые
    4 символа + длина, `app/scan/secrets.py:186` `_mask`, сырой секрет никогда
    не хранится — `app/scan/secrets.py:178`).
- **НЕТ:** email, IP, имени, Telegram id. Полный текст кода не хранится.
- `access_token` — 128-битный per-row секрет-«способность» для чтения отчёта
  по ссылке (`migrations/0010`), не относится к человеку.

### `fixpack_jobs` (`migrations/0001`, расширена 0007/0011/0012)
Колонки: `id`, `audit_id`, `pack`, `stack`, `verified`, `detail`,
`preview_local_url`, `preview_expires_at`, `pr_url`, `pr_delivered`,
`created_at`, `status` (0007), `started_at`/`attempts` (0011),
`access_token` (0012).
- **Идентифицирующее:** `pr_url` — URL созданного pull request
  (`github.com/<owner>/<repo>/pull/N`, косвенно указывает на владельца репо);
  `detail` — текст результата сборки/верификации (может содержать фрагменты
  вывода инструментов по коду пользователя).
- **НЕТ:** email/IP/имени.

### `accounts` (`migrations/0003`, расширена 0009)
Колонки: `id`, `api_key`, `tier`, `created_at`, `key_prefix` (0009),
`key_hash` (0009).
- **Аккаунт не привязан к email/паролю/имени.** Идентификация — только по
  непрозрачному серверному API-ключу `sk_live_<random>`
  (`migrations/0003_accounts_tiers_payments.sql:82-88`).
- `api_key` (plaintext) — **устаревшая, deprecated** колонка; новые аккаунты
  хранят только `key_prefix` (первые ~12 символов, безопасно для логов) и
  `key_hash` = HMAC-SHA256(server_pepper, full_key). Pepper (`API_KEY_PEPPER`)
  только в окружении, не в БД (`migrations/0009_accounts_key_hash.sql:259-277`).
- **НЕТ никакой PII.** Аккаунт = «кто-то, кто заплатил», без личности.

### `payments` (`migrations/0003`, расширена 0004/0005/0007/0018)
Колонки: `id`, `account_id`, `provider`, `external_ref`, `amount`, `currency`,
`status`, `tier_granted`, `created_at`, `telegram_chat_id` (0005),
`product` (0007), `audit_id` (0007), `paypal_order_id` (0018).
Точный INSERT: `app/db.py:967-977`.
- **Идентифицирующее:**
  - `telegram_chat_id` (текст) — id чата Telegram плательщика; сохраняется для
    восстановления ключа командами `/mykey` и `/link`
    (`migrations/0005_payments_telegram_chat_id.sql`).
  - `external_ref` — id платежа провайдера (Stars charge id / on-chain TRC20
    tx id / PayPal capture id).
- Подробнее по провайдерам — см. §5.

### `subscriptions` (`migrations/0015`, расширена 0016/0018)
Колонки: `id`, `account_id`, `telegram_user_id`, `telegram_chat_id`, `tier`,
`invoice_payload`, `telegram_payment_charge_id`, `status`, `expires_at`,
`created_at`, `updated_at`, `repo_full_name` (0016), `last_monitored_at` (0016),
`payment_provider` (0018), `paypal_subscription_id` (0018).
- **Идентифицирующее:**
  - `telegram_user_id`, `telegram_chat_id` — Telegram-идентичность подписчика.
  - `repo_full_name` — канонический `owner/repo` отслеживаемого репозитория
    (`migrations/0016_subscriptions_monitoring.sql`).
  - `paypal_subscription_id` — PayPal id подписки `I-XXXX` (0018).
- **НЕТ:** email/имени/IP.

### `monitoring_runs` (`migrations/0017`)
Колонки: `id`, `repo_full_name`, `status`, `attempts`, `started_at`, `error`,
`created_at`, `completed_at`.
- **Идентифицирующее:** `repo_full_name` (`owner/repo`). Больше ничего —
  список подписчиков и baseline читаются на лету при обработке
  (`migrations/0017_monitoring_runs.sql:659-663`).

### `fix_outcomes` (`migrations/0014`)
Колонки: `id`, `fixpack_job_id`, `audit_id`, `rule_ids` (jsonb), `stack`,
`outcome`, `is_regression`, `pr_url`, `pr_merged`, `created_at`, `updated_at`.
- **Идентифицирующее:** `pr_url` (URL PR, косвенно → владелец репо). `rule_ids`
  — только строковые id правил, не код.

### Не в БД: IP-адреса
IP используется только rate-limiter'ом (`app/ratelimit.py:6`,
ключ = client IP) в памяти процесса или в Redis (`REDIS_URL`, опционально). В
Postgres IP **не пишется**.

---

## 2. Куда уходит код пользователя при аудите — САМОЕ ВАЖНОЕ

### Путь intake → анализ
Эндпоинт `POST /v1/audits` (`app/main.py:1779`). Ровно один из двух источников:
- **zip-загрузка** (`archive`): байты читаются в память —
  `app/main.py:1818` `raw = await archive.read(...)`.
- **repo_url** (публичный `github.com/<owner>/<repo>`): URL валидируется до
  чистых `owner/repo` (SSRF-гард, `app/main.py:1831` `_parse_github_repo_url`),
  затем скачивается zipball с `https://api.github.com` **без авторизации,
  только публичные репо** (`app/ingest/github_fetch.py:20-27`, `GITHUB_API`).
  Приватный репо → 404, недостижим (`github_fetch.py:60-66`).

Далее оба пути идентичны и работают **полностью в памяти** (`io.BytesIO`):
- Валидация zip **без распаковки на диск** (`app/ingest/validators.py:59`
  `validate_zip` — читает только метаданные архива, символьные ссылки
  пропускаются и не извлекаются).
- Лимит размера: **50 МБ сжатых** (`MAX_ARCHIVE_BYTES`,
  `app/ingest/validators.py:25`), 500 МБ распакованных, ≤5000 файлов.

### Что именно уходит на LLM
Стадия `run_llm_scan` (`app/scan/llm_scan.py:246`). **НЕ весь код целиком** —
многоступенчатый фильтр:
1. **Фильтр по типам/директориям** (`_iter_code_files`,
   `app/scan/llm_scan.py:170-184`): пропускаются `node_modules/`, `.git/`,
   `dist/`, `.next/`, `build/`, `.venv/`, `venv/` (`_SKIP_DIRS`); берутся только
   расширения `.ts .tsx .js .jsx .py .sql .toml .yaml .yml .json`
   (`_CODE_SUFFIXES`); бинарные (нулевой байт в первых 4 КБ) и символьные
   ссылки пропускаются. **Нет чтения `.gitignore` пользователя** — фильтр
   захардкожен в этом списке.
2. **Отбор по рубрике** (`select_files`, `app/scan/llm_scan.py:199-215`): из
   отфильтрованных берутся только файлы, чей путь ИЛИ содержимое совпадает с
   regex-ключевыми словами рубрики (две рубрики: `auth`, `security`,
   `app/scan/llm_scan.py:33-70`).
3. **Обрезка**: каждый файл ≤ `MAX_FILE_CHARS = 24_000` символов; суммарный
   бюджет промпта ≤ `MAX_TOTAL_CHARS = 360_000` символов (~90–100K токенов на
   рубрику) (`app/scan/llm_scan.py:29-31`, `select_files:210-214`).
4. Содержимое файлов вставляется в user-промпт в тегах `<file path="...">` с
   нумерацией строк (`build_prompt`, `app/scan/llm_scan.py:218-230`).

Итог: на внешний LLM уходят **фрагменты кода** (совпавшие по ключевым словам
файлы, каждый обрезан до 24К символов), а не весь репозиторий и не произвольные
файлы. Бесплатный аудит — 1 проход; платный Fix Pack — 2 прохода
(`app/scan/llm_scan.py:passes`, комментарий 233-244).

### Куда физически уходят эти фрагменты
`LLMClient` (`app/llm/client.py`). Цепочка провайдеров из окружения
(`providers_from_env`, `app/llm/client.py:37-56`):
1. **AITunnel** (OpenAI-совместимый, `POST {AITUNNEL_BASE_URL}/chat/completions`)
   — **первый**, если заданы `AITUNNEL_API_KEY` и `AITUNNEL_BASE_URL`
   (`app/llm/client.py:44-47`, вызов `app/llm/client.py:129-145`). Это внешний
   LLM-прокси (`api.aitunnel.ru` в проде, см. `.env.example` и README).
2. **Anthropic напрямую** (`POST https://api.anthropic.com/v1/messages`) — только
   если задан `ANTHROPIC_API_KEY` (`app/llm/client.py:49-52`). В `.env.example:22`
   отмечено, что прямой Anthropic **гео-блокирован с RU-хостинга**, поэтому в
   проде основной путь — AITunnel.

Модель: `LLM_MODEL` (по умолчанию `claude-sonnet-4-6`, `app/llm/client.py:22`).
За AITunnel стоит Claude (Anthropic) — какие именно апстрим-провайдеры у прокси,
из кода не выводится дальше «это Claude-совместимая модель».

### Что сохраняется в БД от кода
Только `findings_json` (+ `score_json`, `content_hash`, `repo_url`). Форма
находки — `ScoredFinding` (`app/scan/scoring.py:34-56`): `rule_id`, `title`,
`severity`, `confidence`, `category`, `file` (путь), `line` (номер), `masked`,
`explanation`, `fix_hint`, `context`.
- **Сырой код в БД не хранится.** Поле LLM `evidence` (дословная строка кода)
  используется **только** для анти-галлюцинационной верификации
  (`verify_finding`, `app/scan/llm_scan.py:265-289`) и **НЕ переносится** в
  `ScoredFinding` (см. конструктор `app/scan/llm_scan.py:290-301` — `evidence`
  там отсутствует).
- Для секретов хранится только маска `первые4****(N chars)`
  (`app/scan/secrets.py:186`, комментарий `:178` «value itself is never
  stored»).
- Хранятся: **пути файлов**, **номера строк**, тексты `title`/`explanation`/
  `fix_hint`.
- `content_hash` — канонический SHA-256 содержимого архива
  (`app/scan/pipeline.py:60` `content_digest`), используется как ключ кэша.

### Хранение кода/zip/репо на диске VPS и автоочистка
- **Путь аудита — на диск ничего не пишется.** Всё в `io.BytesIO`; распаковки
  нет (`validators.py`). После ответа байты `raw` живут только в памяти запроса.
- **Fix Pack / Deploy Pack** пишут во временные каталоги:
  `tempfile.mkdtemp(prefix="shipit-semcheck-")` (`app/fixpack/semantic_check.py:376,479`)
  и `tempfile.mkdtemp(prefix="shipit-deploypack-")` (`app/deploypack/pipeline.py:73`)
  — распаковка кода клиента в каталог, монтируемый в Docker-контейнер для
  установки/запуска (semantic check). Это per-job временные каталоги.
- **Ephemeral preview-хостинг**: контейнеры с TTL `preview_expires_at`
  (`fixpack_jobs`), очищаются reaper'ом `POST /internal/preview/reap`
  (`app/main.py:503`), запускаемым `shipit-reap.timer` (systemd, ежечасно,
  README:370). Reaper также сносит контейнеры по label `shipit.expires_at`
  независимо от памяти процесса (`app/main.py:531-535`).
- **TTL на строки `audits`/`payments`/`subscriptions` отсутствует** — они
  хранятся бессрочно (кэш по `content_hash` намеренно переиспользует старые
  строки, `app/main.py:1912-1930`).

---

## 3. Внешние сервисы / субпроцессоры, получающие данные пользователя

| Сервис | Что получает | Ссылки |
|---|---|---|
| **Supabase (Postgres)** | Все таблицы из §1 (метаданные аудитов, находки, платежи, подписки, Telegram id). Подключение через Session Pooler (`DATABASE_URL`). | `app/db.py`, `.env.example` (блок `DATABASE_URL`) |
| **AITunnel** (`api.aitunnel.ru`, LLM-прокси) | **Фрагменты кода пользователя** (см. §2) в теле промпта. Основной LLM-путь. За ним — Claude-совместимая модель. | `app/llm/client.py:44-47,129-145`, `.env.example` (блок AITunnel) |
| **Anthropic** (`api.anthropic.com`) | Те же фрагменты кода — только как fallback, если задан `ANTHROPIC_API_KEY` (в проде гео-блокирован с RU). | `app/llm/client.py:49-52,101-124` |
| **GitHub** (`api.github.com`, `codeload.github.com`) | (а) При intake по URL — скачивание zipball публичного репо, **без токена**. (б) GitHub App: installation-токены для открытия Fix Pack PR; вебхуки `push`/`pull_request`. | `app/ingest/github_fetch.py`, `app/deploypack/github_app.py`, `app/main.py:697` |
| **Telegram Bot API** | `chat_id`, `user_id`, payment charge id; исходящие DM: ключ API, алерты мониторинга (`repo_full_name` + список находок rule_id/file/severity). | `app/billing/telegram_stars.py`, `app/main.py:632,899-917` |
| **PayPal** (Orders/Subscriptions/Webhooks) | Order id, capture/sale id, subscription id, суммы. Публичная половина client id уходит во фронтенд. | `app/billing/paypal.py`, `app/main.py:1065,1165,1220` |
| **TRON-сеть через TronGrid** (`api.trongrid.io`) | Чтение входящих USDT-переводов на **один фиксированный** адрес получателя (`USDT_TRC20_ADDRESS`, публичный). On-chain tx id сохраняется как `external_ref`. | `app/billing/usdt_trc20.py:3-9,50,176` |
| **Timeweb VPS** (`45.10.40.169`) | Хостинг backend; здесь код обрабатывается в памяти. Timeweb — российский хостинг (локация выводима из IP/README, страна в коде явно не названа). | README:360-367 |
| **Vercel** | Хостинг фронтенда (отдельный деплой, кросс-ориджин вызовы к API). | README:12, `.env.example` (CORS/Vercel previews) |
| **Redis** (опционально) | Ключи rate-limit по IP (только если задан `REDIS_URL`). IP в Postgres не пишется. | `app/ratelimit.py`, `.env.example` (REDIS_URL) |

### GitHub App — права (scopes)
В коде нет манифеста с явным списком permissions (настраивается вручную в UI
GitHub, README:448-454). Из использования выводится минимально необходимое:
- **Metadata: read** — резолв installation по репо (`GET /repos/{owner}/{repo}/installation`,
  `app/deploypack/github_app.py:222,268`).
- **Pull requests: write** + **Contents: write** — открытие Fix Pack PR через
  installation-токен (`app/deploypack/github_app.py:201-256`, короткоживущий
  1-часовой токен, scoped на installation).
- Подписки на события вебхука: **Pull request** и **Push**
  (`app/main.py:725-727`, README:451-452).
- App slug: `aiagent2046-coder-shipit` (`.env.example`, `GITHUB_APP_SLUG`).

### Регион Supabase
В коде указан только ref проекта `ytrcwipdgffxtpatrnns`
(`migrations/0002:...66`). **Физический регион в коде явно не задан** — его
нужно уточнить в самом дашборде Supabase.

---

## 4. Cookies / localStorage / sessionStorage на фронтенде

Полный перечень ключей, записываемых в браузер (grep по `web/src/`):

| Хранилище | Ключ | Что хранит | Файл |
|---|---|---|---|
| **localStorage** | `shipit-theme` | Выбор темы (light/dark) | `web/src/components/providers.tsx:16,49`; ранняя загрузка в inline-скрипте `web/src/app/layout.tsx:23` |
| **sessionStorage** | `shipit-api-key` | API-ключ (bearer). Намеренно sessionStorage, а не localStorage — комментарий: bearer-токен, XSS мог бы его вытащить, tab-scope снижает риск (`providers.tsx:102-104`) | `web/src/components/providers.tsx:70,108,120,128` |
| **sessionStorage** | `shipit-audit-<id>` | Результат аудита (JSON) — передача с формы на страницу результата, т.к. POST может идти до ~2 мин | `web/src/components/AuditForm.tsx:15,45`; чтение `web/src/app/audit/[id]/page.tsx:58-60` |
| **sessionStorage** | `drydock:github-install-return` | URL для возврата после установки GitHub App | `web/src/components/FixpackPurchase.tsx:23,186`; чтение `web/src/app/github/installed/page.tsx:9,31` |

- **Cookies (`document.cookie`) не используются** — совпадений нет.
- **Аналитики нет** — не найдено Vercel Analytics, gtag, posthog и т.п.
- Публичные env, попадающие в бандл браузера (не хранилище, но выставлены
  наружу): `NEXT_PUBLIC_API_BASE_URL`, `NEXT_PUBLIC_TELEGRAM_BOT_USERNAME`,
  `NEXT_PUBLIC_PAYPAL_CLIENT_ID` (публичная половина) — `web/src/lib/api.ts:19-28`.

---

## 5. Payment-related данные

Карточные данные через backend **не проходят** — их обрабатывают
Telegram/PayPal/крипто-кошелёк. Мы сами пишем в `payments` только
(`app/db.py:967-977`): `account_id`, `provider`, `external_ref`, `amount`,
`currency`, `status`, `tier_granted`, `product`, `audit_id`, `paypal_order_id`,
`telegram_chat_id`. **Ни номеров карт, ни имени, ни email плательщика.**

По провайдерам:
- **Telegram Stars** (`app/billing/telegram_stars.py`): `external_ref` =
  `telegram_payment_charge_id`; `telegram_chat_id` сохраняется
  (для `/mykey`); суммы в Stars. Для подписок в `subscriptions` —
  `telegram_user_id`, `telegram_chat_id`, `telegram_payment_charge_id`,
  `invoice_payload`.
- **USDT/TRC20** (`app/billing/usdt_trc20.py`): `external_ref` = **on-chain
  transaction id**; адрес-получатель **один фиксированный** и публичный
  (`USDT_TRC20_ADDRESS`), **не** хранится по каждому платежу
  (`usdt_trc20.py:3-9`). Адрес плательщика в `payments` не пишется;
  идентичность появляется опционально через `/link <tx_hash>` (→
  `telegram_chat_id`). Poller читает переводы через TronGrid.
- **PayPal** (`app/billing/paypal.py`): при создании ордера
  `account_id=None, external_ref=None`, пишется `paypal_order_id`
  (`paypal.py:268-276`); при захвате webhook'ом `external_ref` = **capture/sale
  id** (`paypal.py:497-505`). Подписки — `paypal_subscription_id` в
  `subscriptions` (`paypal.py:363-379`). **Email/имя плательщика PayPal в наши
  таблицы не пишутся.**

---

## 6. Retention / удаление данных — что технически возможно СЕЙЧАС

- **Удаление аккаунта/данных пользователем: НЕТ, отсутствует технически.**
  DELETE-эндпоинтов для пользовательских данных нет (grep по `app/`: все
  совпадения `delete` относятся к `plan.deletions` в Fix Pack-генераторе и
  `on delete` в FK, не к удалению по запросу пользователя).
- **«Показать, какие данные о мне хранятся»: НЕТ, отсутствует технически.**
  Единственный «профильный» эндпоинт — `GET /v1/account`
  (`app/main.py:606-630`) — возвращает только `tier`, `authenticated`,
  `entitlements` и **никогда не отдаёт сами данные и даже не эхонит API-ключ**.
- Строки `audits`/`payments`/`subscriptions`/`fix_outcomes` **хранятся
  бессрочно**, TTL нет. Автоочистка есть только у ephemeral preview-контейнеров
  (`preview_expires_at` + reaper, §2) — это временный хостинг превью, не данные
  аккаунта.
- Что есть для пользователя из «самообслуживания»: восстановление API-ключа
  через Telegram-бот — `/mykey` и `/link <tx_hash>`
  (`migrations/0005:...166-172`). Это доступ, а не удаление/экспорт.

---

## 7. Возраст / несовершеннолетние

- **Проверок возраста в коде нет** — не найдено ни одной age-верификации,
  чекбокса «18+», ни в backend, ни во фронтенде.
- Платежи делегированы Telegram Stars / PayPal / крипто-кошельку — возрастное
  регулирование, если есть, происходит на их стороне, не у нас.

---

## Сводка ключевых фактов для документа

1. Личность пользователя нигде не собирается как email/имя/пароль. Максимум
   идентификаторов: `telegram_user_id`/`telegram_chat_id` (у платящих через
   Stars и подписчиков), `repo_url`/`repo_full_name`/`pr_url` (косвенно →
   GitHub-аккаунт владельца репо), on-chain USDT tx id, PayPal order/capture/
   subscription id. IP — только для rate-limit, не в БД.
2. Код пользователя уходит на внешний LLM-прокси **AITunnel** (fallback —
   Anthropic напрямую), но **не целиком**: только совпавшие по ключевым словам
   файлы допустимых типов, обрезанные до 24К символов каждый и 360К суммарно.
3. Полный текст кода в БД **не хранится** — только пути, номера строк, описания
   находок и маскированные превью секретов. На диск VPS путь аудита ничего не
   пишет (всё в памяти); диск задействован лишь во временных каталогах Fix
   Pack/Deploy Pack и в ephemeral-превью с reaper'ом.
4. Механизмов удаления или экспорта пользовательских данных **нет**.
5. Проверок возраста **нет**.
