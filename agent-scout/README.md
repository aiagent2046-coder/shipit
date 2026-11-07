# agent-scout

Автономный внешний скаут безопасности поверх движка drydock (shipit).
Пассивная разведка публичных проектов → сопоставление с advisory/KEV-базой
drydock → отчёт + черновик coordinated disclosure правообладателю.

## Модели работы

- **passive** (по умолчанию, «свободная охота»): только публичные данные и
  GET/HEAD-запросы. Никакой эксплуатации, никакого доступа к данным.
  Цель: найти реальные проблемы (KEV-first) и связаться с правообладателем.
- **active** (ручное переключение, по договору): полный движок + доступ к
  контуру цели, включая БД (read-only). Работает только при наличии записи
  авторизации (`scout auth add --contract ID --scope HOST`), со сроком
  действия и scope. Просроченная запись = отказ.

Контур заложен в код (scout/guard.py, scout/active.py), а не в договорённостях.

## Установка

    python3 -m venv .venv && source .venv/bin/activate
    pip install -e . pytest
    export SCOUT_SHIPIT_ROOT=~/shipit   # чекаут drydock-движка

Для active-режима (аудит static+llm, БД-сессии) — дополнительные
зависимости движка и драйверы:

    pip install -e '.[active]'

## Использование

    # пассивное сканирование публичного репозитория
    scout scan --repo owner/name --out out/

    # профиль сайта + контакты (security.txt) + публичные манифесты
    scout scan --url https://project.example --repo owner/name --out out/

    # свободная охота: поиск кандидатов, сканирование, KEV-first рейтинг
    scout hunt --query "language:javascript pushed:>2026-01-01" --limit 10
    # второй источник кандидатов (синтаксис запроса — как у самого источника):
    scout hunt --query "langflow" --limit 10 --source gitlab

    # договор: запись авторизации для active-режима (ручной акт)
    scout auth add --contract ID --scope db.target.example --hours 24

    # реестр отправленного: статусы drafted -> sent -> read -> fixed
    scout registry list
    scout registry mark <target|fingerprint> sent|read|fixed --note "why"
    # верификация "fixed" по записанным advisory; --re-record дописывает
    # базлайн старым записям, созданным до появления списка advisory
    scout registry refresh [--re-record]

    # доставка писем: явная команда, квоты из реестра (5/день, 1 на контакт),
    # SMTP-конфиг SCOUT_SMTP_* (HOST/PORT/USER/PASSWORD/FROM), без него — отказ
    scout outreach send --dry-run
    scout outreach send --limit 3

    # active mode (по договору, только после auth add):
    # полный прогон drydock static+llm + глубинный отчёт
    scout audit --contract ID --repo owner/name --out out/
    scout audit --contract ID --repo owner/name --osv --llm-cost-cap 5
    # read-only БД-сессия: scope-проверка до подключения, audit-лог
    export SCOUT_DB_DSN='postgresql://...'   # DSN только из env, не из argv
    scout db query --contract ID --target db.host.example \
        "SELECT count(*) FROM pg_tables"

## Выход

- `*-report.md` — полный технический отчёт (ограничения движка — дословно).
- `*-outreach.md` — короткое письмо правообладателю: доказательство, не
  эксплойт; оффер договора для глубинного анализа (root cause, БД).

## Правовой контур

passive — OSINT + публичные артефакты (RFC 9116 security.txt, публичные
репозитории, заголовки). Активное сканирование и доступ к БД — только по
договору (ISO/IEC 29147, таймлайн 90 дней). Чужие данные не читаются даже
при технической доступности: сообщить о факте — да, пользоваться — нет.

## Тесты

    python -m pytest -q

Фикстуры используют реальные записи пинового advisory-снапшота shipit,
включая KEV-кейс (langflow 1.2.0).

Сетевые пути юнит-тесты не трогают (всё на fake/mocks). Живой смоук
реального контура — песочный HOME, операторский реестр не трогается:

    bash scripts/live_smoke.sh     # ~3 минуты, exit 0 = SMOKE OK

Гоняет: scan --url, scan --repo, hunt --source gitlab, registry list,
registry refresh --re-record, outreach send --dry-run. Rate limit
удалённого API — видимый SKIP, не тихий PASS.
