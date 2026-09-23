# Реальный npm эксперимент: mkdirp 0.5.0 / minimist

Статус: **PASSED для указанной зависимости и проверенных сценариев**, не для
безопасности всего исторического проекта.

Источник: [isaacs/node-mkdirp](https://github.com/isaacs/node-mkdirp), тег `0.5.0`,
commit `b98bedf92798ed73c87413eaf413d01dbe094a09`.
Исходный package.json действительно закрепляет `minimist: "0.0.8"`.
Upstream lockfile отсутствует: baseline lock отдельно создан npm 11.9.0 из
неизменённого manifest. Он сохранён для точного повторения разрешения зависимостей.

Scanner: production commit `0b5c981412ad0a9ab62ad4a7a6da1b90a0acd67b`;
catalog SHA-256 `e8cc8c6a60e29331c42f0c50bbdb57484766b947d377afc966c723ec7b3347af`.
Среда: Node `24.19.0`, npm `11.9.0`, Linux. Карточка `npm-dependency-upgrade`
предлагает `0.2.4`, проверенную против всех двух advisory entries minimist.

| Проверка | До | После | Восстановление |
| --- | --- | --- | --- |
| Корневой minimist | 0.0.8 | 0.2.4 | 0.0.8 |
| Находки minimist | 2 | 0 | 2 |
| Локальная prototype-pollution регрессия | Воспроизводится | Блокируется | Воспроизводится |
| Родные тесты mkdirp.js + sync.js | 9 assertions прошли | 9 прошли | 9 прошли |
| CLI: два пути, mode 0700, help | 5 проверок прошли | 5 прошли | 5 прошли |

Вторая установленная копия minimist остаётся `1.2.8`, unaffected во всех стадиях.
Версии всех остальных установленных зависимостей не изменились. `npm ls minimist
--all --json` проходит на каждой стадии. Все target advisory entries после
исправления имеют `unaffected`, не `unknown`; установленные версии совпадают с lock.
После восстановления manifest, baseline lock, scan и dependency probe совпадают
с исходной стадией. Общие affected assessments проекта: `9 → 7 → 9`, поэтому
оставшиеся проблемы не скрыты.

Независимая регрессия адаптирует локальный constructor-function случай из
[minimist v1.2.6 test/proto.js](https://github.com/minimistjs/minimist/blob/7efb22a518b53b06f5b02a1038a88bd6290c2846/test/proto.js).
Маркер в Function.prototype немедленно удаляется; каждый probe работает отдельным
процессом. Это проверка ошибки зависимости. Удалённый exploit mkdirp не заявляется.
См. MINIMIST-LICENSE.txt и THIRD-PARTY-NOTICES.md.

## Воспроизведение

Нужны scanner checkout с кодом указанного production commit, его Python environment,
Node/npm приведённых версий и доступ к публичным GitHub/npm. Расположите рядом
`run-mkdirp.py`, `mkdirp-probe.cjs`, `baseline-lock.json`.

```bash
git clone --branch 0.5.0 --depth 1 https://github.com/isaacs/node-mkdirp.git mkdirp-source
git -C mkdirp-source rev-parse HEAD
/path/to/scanner/.venv/bin/python run-mkdirp.py \
  --scanner-root /path/to/scanner \
  --source mkdirp-source \
  --baseline-lock baseline-lock.json \
  --output reproduced-evidence
```

`--output` должен быть новым каталогом. SHA-256 сохранённого baseline lock
проверяется: `dc3f4d520dddd39577c5e3ce54c7d547cf990d36eb516a4893e0b820a1c75013`.
Без `--baseline-lock` runner выполняет отдельную новую подготовку через npm и
фиксирует полученный lock; разрешение транзитивных зависимостей может отличаться
от сохранённого эксперимента.

Runner применяет только `npm pkg set dependencies.minimist=0.2.4` и
`npm install --package-lock-only`; lock вручную не редактируется. Установки:
`npm ci --ignore-scripts --no-audit --no-fund`. Lifecycle scripts отключены,
проверенные upstream тесты и собственный probe запускаются явно.
Используется отдельный HOME без наследования пользовательского npm config.

Коды выхода: 0 — passed, 1 — нарушен контракт, 2 — выполнение unavailable.
Полный старый upstream suite не запускался; проверены два исходных тестовых файла
и CLI, реально использующий minimist. Наличие пакета вне каталога не означает его
безопасность. Это исследовательский эксперимент в отдельных копиях, не автоматическое
исправление пользовательского проекта.

## Сохранённые доказательства

[Сводка](evidence/summary.json) содержит карточки, target findings, оценки каждой
установленной копии, результаты probe и контрольные суммы файлов.
[Полный архив](evidence/raw-evidence.tar.xz) сохраняет исходные JSON, manifests,
lockfiles и логи. Краткие логи тестов и probe также доступны в `evidence/`.

После успешного цикла runner получил дополнительные проверки входного baseline
lock и уточнённые коды ошибок. Повторные установки ради этих изменений не
выполнялись: сохранены результаты первого цикла, проверены синтаксис, lint и
интерфейс запуска окончательного runner.
