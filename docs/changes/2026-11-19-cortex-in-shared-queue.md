# Кейси Cortex у спільній черзі з офенсами QRadar (за прапорцем, вимкнено)

Крок 2 з 3. Мета — обробляти офенси й кейси разом, у порядку спадання пріоритету, а не окремо (офенси воркером, Cortex раз на добу о 09:30).

## Що додано
- `queue_db.py`: джерело `cortex`; `cortex_key(incident_id)` = `-incident_id` (id офенсів додатні, колізій нема). Порядок `ORDER_BY` не змінено.
- `cortex_queue.py` (новий, без побічних ефектів при імпорті):
  - `produce()` — викликає `poller.py` (кожні 10 хв, окремий try): кладе нові кейси `new`/`under_investigation`; magnitude з `cortex_queue_severity_magnitude` (critical 9, high 8, medium 6, low 4, informational 2); запобіжники `cortex_queue_max_per_run` (40) і `cortex_queue_daily_cap` (200 нових за добу);
  - `process()` — викликає `worker.py` (гілка `source='cortex'`, без `/process-one`): свіжий стан кейсу (`incident_id_list`) і той самий код, що й о 09:30, — `run_triage(..., incidents=[inc])`: закрити шум / призначити / розбір Vertex / нотатка / кореляція з QRadar. Поважає `cortex_queue_dry_run` (типово true) і `cortex_incident_dry_run` — пише в Cortex лише коли вимкнені обидва; результат dry-run після переходу на apply переставляється в чергу.
- `cortex_incident_triage.run_triage` отримала необов'язковий `incidents=`; при ввімкненому прапорці 09:30-прогін пропускає кейси, що зараз у черзі (`kept.in_queue`), щоб не обробляти двічі.
- Ключі `cortex_queue_*` у `config_schema.py` та `DEFAULTS`; `tests/smoke_test.py::check_queue_db` покриває змішаний порядок, продюсер, ліміти, dry-run → apply.

## Поведінка
- `cortex_queue_enabled=false` (типово): нічого не змінюється.
- Верифіковано на Cortex (лише читання): фільтр `incident_id_list` повертає один кейс, для відсутнього — порожньо.
- Вердикти Cortex лишаються на Vertex; перенесення на локальну модель — окремий виміряний крок.

## Далі (крок 3)
Увімкнути `cortex_queue_enabled` спочатку в dry-run, подивитись у `worker.log`/`poller.log`, потім apply; звіт 09:30 читатиме стан з таблиць, а не лише з живого списку.

## Дописано того ж дня: свіжий конфіг для кейсів Cortex
`worker.py` читає `config.json` один раз на старті прогону, а прогін дренує чергу годинами — перемикання `cortex_queue_dry_run` не діяло, і кейси повторно оброблялись у dry-run. `cortex_queue.process()` тепер перечитує конфіг із диска на кожен кейс (збій читання → конфіг воркера з попередженням).

## Прод-стан після ввімкнення (хост, не код)
- `cortex_queue_enabled=true`, `cortex_queue_dry_run=false` у config.json mdlwr01 (бекапи `config.json.bak_queue_*`): черга закриває шум, призначає й розбирає кейси Cortex безперервно, разом з офенсами QRadar.
- `cortex_xdr_scan.timer` (09:30) **вимкнено** (`systemctl disable --now`) за рішенням власника: щоденний звіт в чат не потрібен, актуальні дані береться з Chat-бота. Тріаж іде через чергу; дайджест незатриманих алертів більше не надсилається. `cortex_endpoint_cleanup.timer` (10:00) без змін. Повернути: `systemctl enable --now cortex_xdr_scan.timer`.
- Крок «звіт 09:30 читає стан із таблиць» скасовано як зайвий.
- `cortex_endpoint_cleanup`: новий ключ `cortex_xdr_cleanup_report` (типово true). `false` — видалення й запис у `cortex_endpoint_deleted` як і раніше, а звіт у чат не шлеться (лише лог), повернуті позначаються. На проді поставлено `false` за рішенням власника (дані дивиться в боті). Таймер 10:00 лишено, бо він реально видаляє endpoint'и (`cortex_xdr_cleanup_dry_run=false`).
