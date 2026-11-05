# 2026-11-05 — Cortex XDR: щоденне видалення ендпоінтів, що мовчать 15 днів і більше

**Статус:** зроблено; на проді бойовий режим (`cortex_xdr_cleanup_dry_run: false`, поріг 15 д) за рішенням користувача.
**Прод:** mdlwr01, `cortex_endpoint_cleanup.timer` щодня 10:00.

## Навіщо

Endpoint Administration у консолі Cortex XDR накопичує записи хостів, яких давно немає
(переустановлені, списані, ноутбуки, що не повертались). Сам Cortex видаляє такий запис лише
через 180 днів «Connection Lost» (за замовчуванням). Користувач хоче прибирати їх раніше —
щодня, коли пристрій мовчить 15 днів і більше.

## Що в API (переміряно 05.11.2026 на тенанті `modernexpo.xdr.eu`)

- `POST /public_api/v1/endpoints/get_endpoint`: фільтр `last_seen` з `lte`/`gte` і значенням у
  мс працює (gte=now−14d → 871, lte → 0); `endpoint_status in [disconnected, lost]` → 117;
  сторінки `search_from/search_to` по 100. Поля: `endpoint_id`, `endpoint_name`,
  `endpoint_status` (CONNECTED/DISCONNECTED/LOST/UNINSTALLED), `last_seen` (мс), `endpoint_type`,
  `ip`, `users`, `group_name`, `is_isolated`, `operational_status`, …
- `POST /public_api/v1/endpoints/delete`: єдиний фільтр `endpoint_id_list` (`in`), до 1000 id за
  запит, відповідь `reply: true`. Видалення з консолі **не деінсталює агент**: якщо хост
  повернеться — зареєструється новим записом. Потрібна роль з правом Endpoint Administration →
  Delete, тому ключ окремий від read-only ключа дайджесту.
- Стан тенанта на 05.11: 871 ендпоінт (754 CONNECTED, 117 DISCONNECTED; 832 робочі станції,
  39 серверів), **жодного з last_seen старшим за 14 днів** (найстарші — 12 записів у вікні
  7–14 д). Тобто перший реальний кандидат з'явиться, коли хтось помовчить два тижні.

## Що зроблено

- `cortex_endpoint_cleanup.py`: кандидати = `get_endpoint(last_seen <= now − N днів)` з
  повторною локальною перевіркою порога → запобіжники (регекси імен
  `cortex_xdr_cleanup_exclude_hostnames`, групи `_exclude_groups`, типи `_exclude_types`, напр.
  `AGENT_TYPE_SERVER`, ізольовані `_skip_isolated`, стеля `_max_per_run` = 100, найдавніші
  першими) → `endpoints/delete` admin-ключем → контрольне читання тих самих id (скільки ще
  віддає консоль) → таблиця `cortex_endpoint_deleted` в `ai_state.db` → звіт у Google Chat
  (`cortex_xdr_webhook_url`, інакше `falcon_pua_webhook_url`). Авторизація, `api_host`,
  `send_to_chat` — імпортуються з `cortex_xdr_scan.py` (той самий Advanced-підпис).
  CLI: `--dry-run` (примусово), `--apply` (перекриває конфіг), `--days N`.
- Безпека: `cortex_xdr_cleanup_dry_run` = **true** у схемі; без `cortex_xdr_admin_api_key_id`/
  `_key` скрипт сам переходить у dry-run; поріг < 1 дня відхиляється; якщо API на delete не
  повернув `true` — state не пишеться, звіт не шлеться.
- `config_schema.py`: 10 ключів `cortex_xdr_cleanup_*` + `cortex_xdr_admin_api_key_id/_key`.
- `systemd/cortex_endpoint_cleanup.{service,timer}` у репо (раніше юніти жили лише на хості);
  таймер щодня 10:00, `Persistent=true`.
- Admin-ключ — Bitwarden «API: Cortex XDR (Privileged IT Admin)» (поля ApiKeyId/ApiKey/ApiUrl),
  записаний у `config.json` на mdlwr01 скриптом (бекап `config.json.bak-<ts>-cortexadmin`).

## Блок «повернулися після видалення» (коміт того ж дня)

Видалення запису не чіпає агент: у 90-денному вікні Cortex відновлює запис при повторному
підключенні («If a deleted endpoint reconnects, Cortex XDR recovers its existing data»), після
вікна потрібен `cytool reconnect` або переустановка, і хост з'являється з новим id. Щоб бачити
обидва випадки, скрипт на кожному прогоні звіряє `cortex_endpoint_deleted` (рядки без
`returned_ts`) з консоллю: за `endpoint_id_list` (→ «відновлено старий запис») і за `hostname`
(інший id → «новий запис (переустановка/reconnect)»); умова — `last_seen` пізніший за
`deleted_ts`. Знайдені йдуть окремим блоком у звіт (звіт шлеться і коли видалень 0), після
успішного webhook позначаються `returned_ts`/`returned_as` (міграція колонок у `init_db`).
Перевірено на живому API: фільтр `hostname in [...]` працює (BUH37, INS16 знайдено).

## Режим на проді

У `config.json` на mdlwr01: `cortex_xdr_cleanup_days: 15`, `cortex_xdr_cleanup_dry_run: false` — таймер
щодня 10:00 видаляє все, що мовчить ≥15 днів (стеля 100 за прогін). Щоб призупинити: поставити
`cortex_xdr_cleanup_dry_run: true` або `systemctl disable --now cortex_endpoint_cleanup.timer`.
Винятки — `cortex_xdr_cleanup_exclude_*`.
