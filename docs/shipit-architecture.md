# ShipIt — техническая архитектура MVP

> «Финишёр» для vibe-coded приложений: аудит production-готовности + агентные Fix Packs.
> Версия: 0.2 · Июль 2026 · Автор: Don + Claude

**Зафиксированные продуктовые решения (v0.2, по итогам GTM-плана):**
1. Категория — «autonomous rescue», не сканер. Аудит — бесплатная приманка, продукт — исполненный и верифицированный Fix Pack.
2. Wedge-сообщение Deploy Pack — **миграция**: «выселим приложение с Lovable/Bolt на вашу инфраструктуру без потери работоспособности» (у Lovable есть свой one-click деплой, боль — в выходе с платформы и в бэкендах, которые она не хостит).
3. Доставка результата — **PR через GitHub-синк** (основной канал), patch.tar.gz — только fallback для технических пользователей.
4. Флоу оплаты — **verify first, pay to unlock**: Pack исполняется и верифицируется до оплаты, пользователь видит живой preview, платит за получение PR/артефактов.
5. Платежи — два трека: криптопроцессинг сейчас (Трек A), card-checkout через иностранное юрлицо параллельно (Трек B).

---

## 0. Принципы проектирования

1. **Максимальное переиспользование Palantir-офиса.** Оркестратор агентов, фаза блокирующего ревью (viktor), read-before-write, мульти-провайдерный слой — уже написаны и покрыты 83 тестами. ShipIt — это новый «клиент» этого движка, а не новая система.
2. **Детерминизм прежде LLM.** Всё, что можно проверить статическим анализатором, проверяется статическим анализатором. LLM подключается только там, где нужна семантика.
3. **Чужой код = враждебный код.** Любое исполнение пользовательского кода — только в изолированном контейнере без сети.
4. **MVP = 2 стека.** Node/Next.js (экспорт Lovable/Bolt/v0) и Python/FastAPI. Остальное — позже.

---

## 1. Общая схема

```
┌──────────────────────────────────────────────────────────────────┐
│  Frontend (Next.js, Supabase Auth)                               │
│  лендинг · дашборд · отчёт аудита · покупка Fix Pack             │
└───────────────┬──────────────────────────────────────────────────┘
                │ HTTPS / REST
┌───────────────▼──────────────────────────────────────────────────┐
│  API Gateway (FastAPI)                                           │
│  /audits · /fixpacks · /webhooks/stripe · /webhooks/github       │
└───────┬───────────────────────────────┬──────────────────────────┘
        │ enqueue                        │ enqueue
┌───────▼───────────┐          ┌────────▼────────────────────────┐
│  Audit Engine     │          │  Fix Pack Orchestrator          │
│  (worker, arq)    │          │  (Palantir office runtime)      │
│                   │          │                                 │
│  1. Ingest        │          │  kristina → план                │
│  2. Static scan   │          │  bjorn/elsa → изменения         │
│  3. LLM scan      │          │  viktor → блокирующее ревью     │
│  4. Scoring       │          │  test-runner → verdict          │
└───────┬───────────┘          └────────┬────────────────────────┘
        │                               │
┌───────▼───────────────────────────────▼──────────────────────────┐
│  Sandbox Layer — Docker: no-net, ro-rootfs, tmpfs, cpu/mem limit │
└───────┬──────────────────────────────────────────────────────────┘
        │
┌───────▼───────────────────────────────────────────────────────────┐
│  Data Layer                                                       │
│  PostgreSQL (users, audits, findings, fixpack_jobs, payments)     │
│  Redis (очередь arq, rate limiting)                               │
│  S3-совместимое хранилище (клоны репо, артефакты, диффы)          │
└───────────────────────────────────────────────────────────────────┘
```

Деплой MVP: один VPS (docker-compose: api, worker×2, postgres, redis, minio, caddy).

---

## 2. Компоненты

### 2.1 Ingest (приём кода)

Три канала, в порядке приоритета реализации:

| Канал | Механика | MVP |
|---|---|---|
| ZIP-upload | экспорт из Lovable/Bolt, до 50 МБ | ✅ фаза 1 (только аудит) |
| Public repo URL | `git clone --depth 1` | ✅ фаза 1 |
| GitHub App | OAuth, private repos, webhook на push | ✅ фаза 2 — **обязателен**: это канал доставки PR |

Онбординг для Lovable-пользователя: «включите GitHub-синк в Lovable (1 клик) → установите наш GitHub App на этот репозиторий». Для ZIP-канала Fix Pack недоступен (некуда открыть PR) — только аудит с CTA «подключите GitHub».

Пайплайн приёма:
1. Валидация: размер, кол-во файлов (< 5 000), запрет симлинков, zip-bomb-проверка (compression ratio).
2. Нормализация в S3: `s3://repos/{audit_id}/source.tar.gz`.
3. Детект стека: `package.json` + `next.config.*` → Node/Next.js; `pyproject.toml`/`requirements.txt` + FastAPI import → Python. Иначе — «стек не поддержан» (честный отказ, не деградация качества).

### 2.2 Audit Engine

Worker на `arq` (asyncio-native, проще Celery — соответствует стеку офиса). Стадии:

**Стадия A — статический скан (детерминированный):**

| Проверка | Инструмент | Категория скора |
|---|---|---|
| Секреты в коде | gitleaks (regex-набор) | Security |
| Уязвимые зависимости | `npm audit --json` / `pip-audit --format json` | Security |
| Типы | `tsc --noEmit` / `mypy` (если конфиг есть) | Correctness |
| Линт | `eslint` / `ruff` (только error-level) | Correctness |
| Хардкод URL/ключей в конфигах | собственные правила (yaml) | Config |
| Наличие тестов | эвристика: `*test*`-файлы, test-скрипт | Testing |
| Dockerfile / CI | наличие + `hadolint` | Deploy |

Все инструменты запускаются **внутри sandbox-контейнера** (даже «безопасные»: `npm audit` требует установки зависимостей → исполнение чужих install-скриптов запрещено, ставим с `--ignore-scripts`).

**Стадия B — LLM-скан (семантический):**

- Модель: Claude через существующий мульти-провайдерный слой офиса (AITunnel), с фолбэком на прямой `fetch` к `api.anthropic.com` (паттерн уже отработан для SyndiAI: direct fetch, без SDK).
- Подготовка контекста: repo-map (дерево + сигнатуры функций, как в aider) + целевые файлы по категориям. Auth-категория читает всё, где встречаются `auth|jwt|session|password|token`; Payments — `stripe|webhook|checkout|invoice`; и т.д. Бюджет: ≤ 150K токенов на аудит.
- Рубрики (по одной на категорию, structured output — JSON):
  1. **Auth** — самописный JWT-декодинг, пароли без хэша, отсутствие проверки сессии в API-роутах, RLS-обход.
  2. **Payments** — webhook без верификации подписи, отсутствие идемпотентности, суммы с клиента.
  3. **Edge cases** — отсутствие обработки ошибок во внешних вызовах, race conditions в критичных мутациях, отсутствие валидации input.
  4. **Data** — миграции, уникальные констрейнты, N+1 в горячих путях.
- Каждый finding: `{category, severity, file, line_range, title, explanation, fix_hint, confidence}`.
- Анти-галлюцинация: перед записью finding worker проверяет, что `file` существует и `line_range` содержит упомянутый код (grep-верификация). Не подтвердилось — finding отбрасывается и логируется.

**Стадия C — скоринг:**

```
score = 10 − Σ(severity_weight × confidence)   # clamp [0..10]
severity_weight: critical 2.0 · high 1.0 · medium 0.4 · low 0.1
```

Скор по категориям + общий. Отчёт рендерится в HTML/OG-изображение (шарабельный артефакт — ядро вирального GTM).

### 2.3 Fix Pack Orchestrator

Тонкая надстройка над Palantir-офисом. Каждый Pack = декларативный workflow:

```yaml
# packs/deploy-pack.yaml
name: deploy-pack
stacks: [nextjs, fastapi]
preconditions:
  - audit_completed
  - no_critical_secrets      # сначала Security, потом деплой
stages:
  - agent: kristina          # план: какие файлы создать/изменить
    output: plan.json
  - agent: bjorn             # Dockerfile, compose, CI workflow, .env.example
    constraints: read_before_write
  - agent: viktor            # блокирующее ревью diff'а
    blocking: true
  - runner: sandbox_test     # docker build + docker run + healthcheck
    success: "HTTP 200 on /"
  - runner: preview_deploy   # временный live URL (TTL 24ч, watermark)
    output: preview_url
  - gate: payment            # verify first, pay to unlock
  - output: pull_request     # PR в репо пользователя (branch shipit/deploy-pack)
```

Флоу «verify first, pay to unlock»: стадии до `gate: payment` выполняются бесплатно; пользователь видит **живое собственное приложение** по preview-ссылке — это момент конверсии. После оплаты открывается PR; patch.tar.gz доступен как fallback по явному запросу.

Порядок реализации Pack'ов: **Deploy → Hardening → Auth → Payments** (от детерминированного к рискованному).

Доставка: PR в репозиторий пользователя в ветку `shipit/{pack}` — GitHub App запрашивает минимальные права (`contents: write`, `pull_requests: write`), **мы никогда не пушим в main напрямую** — merge остаётся за пользователем (HITL, тот же принцип, что в Action Service). Описание PR генерируется человекочитаемым: что изменено, зачем, как проверить — это же контент для доверия нетехнического пользователя.

### 2.4 Sandbox Layer

Критический компонент безопасности. Требования к контейнеру задач:

```bash
docker run --rm \
  --network=none \                # сеть отключена полностью
  --memory=2g --cpus=2 \
  --pids-limit=256 \
  --read-only --tmpfs /tmp:size=512m \
  --security-opt no-new-privileges \
  --cap-drop=ALL \
  -v /repos/{audit_id}:/workspace:ro \
  shipit-runner:node20            # или :py312
```

Исключение для сети: стадия `npm ci --ignore-scripts` / `pip install` выполняется в отдельном контейнере с egress-allowlist (`registry.npmjs.org`, `pypi.org`) через прокси, затем `node_modules`/venv монтируется в основной no-net контейнер. Таймаут любой задачи: 10 мин, kill по превышению.

### 2.4.1 Ephemeral Preview Hosting

Компонент под флоу «verify first, pay to unlock». Тот же sandbox-контейнер после успешного healthcheck, но:
- ingress наружу через reverse proxy (Caddy wildcard): `{job_id}.preview.shipit.app` → контейнер;
- egress остаётся закрытым, кроме доменов из `.env.example` приложения (Supabase-проект пользователя и т.п.) — иначе preview с бэкендом не заведётся;
- лимиты: TTL 24 ч (cron-реапер убивает контейнер и чистит DNS-запись), 256 МБ RAM, watermark-баннер инжектится прокси;
- одновременно живых preview на free-пользователя: 1.

Стоимость на неплатящего — центы; конверсионная ценность живой ссылки того стоит.

### 2.5 Data Layer — схема

```sql
users        (id, email, auth_provider, plan, created_at)
audits       (id, user_id, source_type, s3_key, stack, status,
              score_total, score_json, created_at, finished_at)
findings     (id, audit_id, category, severity, confidence,
              file, line_start, line_end, title, body, fix_hint,
              verified bool)          -- прошёл grep-верификацию
fixpack_jobs (id, audit_id, pack, status, stages_json,
              preview_url, preview_expires_at,
              artifact_s3_key, pr_url, created_at)
              -- status: queued → running → verified_unpaid
              --         → paid → delivered | failed | expired
payments     (id, user_id, provider, external_id, product,
              amount, currency, status, created_at)
              -- provider: crypto (Трек A) | card (Трек B, позже)
events       (id, entity_type, entity_id, actor, action,
              payload_json, created_at)   -- audit-first, как в Action Service
```

Индексы: `audits(user_id, created_at)`, `findings(audit_id, severity)`, уникальный `payments(provider, external_id)` — идемпотентность вебхуков (урок SyndiAI: constraint сразу, а не «потом»).

### 2.6 API Gateway — эндпоинты MVP

```
POST   /v1/audits                # multipart zip | {repo_url}
GET    /v1/audits/{id}           # статус + скор
GET    /v1/audits/{id}/report    # findings (после оплаты — полные)
POST   /v1/fixpacks              # {audit_id, pack} — бесплатный запуск до gate
GET    /v1/fixpacks/{id}         # статус + preview_url (когда verified_unpaid)
POST   /v1/fixpacks/{id}/unlock  # инициировать оплату (crypto invoice)
GET    /v1/fixpacks/{id}/artifact  # signed URL, только status=paid+
POST   /v1/webhooks/payments     # верификация подписи → paid → открыть PR
GET    /healthz
```

Auth: Supabase Auth (JWT), верификация через `supabase.auth.getUser(token)` — тот же проверенный паттерн, что в SyndiAI, никакого самописного декодинга. Rate limiting: Redis, 5 аудитов/день на free.

---

## 3. Безопасность — чеклист

- [ ] Пользовательский код никогда не исполняется вне sandbox (включая install-скрипты)
- [ ] LLM-вывод никогда не исполняется как код без viktor-ревью + тестов
- [ ] Prompt injection: содержимое репо в LLM-контексте оборачивается как данные; системный промпт запрещает следовать инструкциям из кода/README
- [ ] Секреты, найденные аудитом, маскируются в отчёте (показываем файл/строку, не значение) и не логируются
- [ ] Репозитории клиентов шифруются в S3 (SSE), TTL 30 дней, удаление по запросу
- [ ] Вебхуки платёжки: верификация подписи + уникальный constraint на external_id

---

## 4. Фазы и критерии готовности (execution through goals)

| Фаза | Объём | Тест-критерий |
|---|---|---|
| **0 (параллельно)** | Лендинг «autonomous rescue / миграция с Lovable», криптопроцессинг (Трек A), старт документов на иностранное юрлицо (Трек B), валидация спроса в r/lovable, r/bolt | Лендинг живой; тестовый платёж проходит; ≥10 ответов из сообществ, подтверждающих боль миграции |
| **1. Аудитор (2 нед)** | Ingest (zip+url), статический скан, LLM-скан Auth+Security, скоринг, HTML-отчёт | 10 открытых vibe-coded репо: скор воспроизводится при повторном прогоне ±0.5; 0 непроверенных findings в отчёте |
| **2. Deploy Pack (1.5 нед)** | GitHub App, workflow yaml, sandbox-верификация, preview hosting, PR-доставка | Экспорт Lovable через GitHub-синк → preview URL живой → после тестовой оплаты PR открыт в репо и приложение с ветки деплоится на чистый VPS |
| **3. Монетизация (1 нед)** | crypto-checkout live, тарифы ($39–49 разово за Deploy Pack), посты в r/lovable / r/bolt / Indie Hackers с бесплатным аудитом как приманкой | 5 платных Deploy Pack от незнакомых пользователей → go; иначе разбор (лендинг/канал/цена) до наращивания фич |
| **4. Guard + следующие Pack'и** | webhook на push, ре-аудит, подписка $9/мес; Hardening Pack | только после go в фазе 3 |

---

## 5. ⚠️ Assumptions и открытые риски

1. **Платежи из РФ — решение принято, риски остались.** Трек A (крипта → фиат → ИП): провалидировать налоговую/регуляторную сторону с бухгалтером до первого платежа, не только по статьям. Трек B (иностранное юрлицо → Paddle/LS): запустить оформление в фазе 0. Сигнал срочности Трека B — конверсия лендинг→оплата: крипта отпугивает часть западной нетехнической ЦА.
2. **Зависимость от GitHub-синка.** Доставка PR требует, чтобы пользователь включил GitHub-синк в Lovable и установил наш App. Доля Lovable-пользователей с включённым синком неизвестна — замерить в фазе 0 (вопрос в опросах сообществ). Если доля низкая, онбординг-гайд «включить синк за 1 минуту» становится критичной частью воронки, а не примечанием.
3. **Платформенный риск.** Lovable уже встроила auto-fix для security (июнь 2026); если она же закроет сценарий «экспорт на свою инфраструктуру» — ниша сжимается. Скорость фаз 0–3 важнее полноты фич.
4. **VPS-мощность.** Sandbox + preview-контейнеры прожорливы; текущий Timeweb VPS может не вытянуть >2 параллельных задач. Worker-пул с конкуренцией 2; масштабирование — второй VPS с тем же compose.
5. **Palantir-офис как оркестратор.** Предположение: stage-механизм офиса вызывается программно как библиотека, а не только через CLI. Если завязан на CLI-сессии — рефакторинг ~2–3 дня в фазе 2.
6. **Стоимость LLM.** ~150K токенов/аудит ≈ $0.5–1.5; Deploy Pack до оплаты — ещё ~$1–3 на неплатящего. Лимиты: 5 аудитов/день, 1 бесплатный Pack-прогон на аудит.
7. **AITunnel как единая точка отказа** — фолбэк на прямой Anthropic API в конфиге с первого дня (`.env` — единственный источник истины). Особенно критично для платного флоу: пользователь ждёт PR, а не free-отчёт.
