# 2026-10-19 — Cortex XDR: дайджест бере алерти з API Cortex, не з QRadar; Falcon-дайджест вимкнено

**Статус:** зроблено. **Прод:** так (mdlwr01).

## Навіщо

- CrowdStrike Falcon замінюється на Cortex XDR (міграція агентів з 10.10). Дайджест Falcon у
  Google Chat більше не потрібен — його вимкнено на прохання користувача.
- `cortex_xdr_scan.py` читав алерти Cortex з QRadar (логсорс `Cortex XDR`, CEF через syslog-ng на
  api-gw). За 14 днів до 19.10 у QRadar **0 подій Cortex XDR** — фід мертвий (як і з 2026-08-04),
  тож сканер, навіть увімкнений, нічого б не бачив. Залежність від ретранслятора прибрано:
  алерти тепер беруться напряму з Cortex XDR Public API.

## Що змінено

1. **Falcon:** на mdlwr01 закоментовано рядок crontab root
   `0 9 * * * … falcon_pua_scan.py` (позначка `# disabled 2026-10-19`). Резервна копія crontab —
   `/root/crontab.bak-20261019-0937`. Скрипт, конфіг і таблиця `falcon_pua_reported` не чіпались.
2. **`cortex_xdr_scan.py`** — джерело `POST /public_api/v1/alerts/get_alerts_multi_events`
   (фільтр `creation_time >= now - lookback`, сторінки по 100, стеля 1000). Автентифікація
   **Advanced** (sha256(key+nonce+timestamp), ключ у запиті не передається). Фільтри
   (severity ≥ Low, allowlist назв/ID, нове — `is_whitelisted`), дедуп по `alert_id` проти
   `cortex_xdr_reported`, формат повідомлення і webhook — без змін. Посилання на алерт —
   `https://<tenant>/alerts/<alert_id>`. Додано `--dry-run` (друкує звіт, не шле й не пише state).
   Код QRadar/AQL/CEF-парсера прибрано.
3. **`config_schema.py`:** прибрано `cortex_xdr_aql_timeout_seconds`, `cortex_xdr_max_aql_rows`,
   `cortex_xdr_logsource_filter`; додано `cortex_xdr_api_fqdn`, `cortex_xdr_api_key_id`,
   `cortex_xdr_api_key`, `cortex_xdr_api_security`, `cortex_xdr_console_url`,
   `cortex_xdr_page_size`, `cortex_xdr_max_alerts`, `cortex_xdr_api_timeout_seconds`,
   `cortex_xdr_skip_whitelisted`.
4. **config.json на mdlwr01:** додано `cortex_xdr_api_fqdn` / `_key_id` / `_key` / `_security`
   (резервна копія `config.json.bak-20261019-cortex`). Ключ — Bitwarden
   «API: Cortex XDR API (read-only)» (роль лише на перегляд, рівень Advanced).
5. **Таймер:** `cortex_xdr_scan.timer` (щодня 09:30, `Persistent=true`) увімкнено.

## Перевірка

- Пробний запит з mdlwr01: HTTP 200, Advanced-підпис приймається.
- Прогін нового коду за 30 днів (без відправки): 6 алертів → 6 у звіті (усі `Prevented (Blocked)`,
  Medium/Low): WildFire ADM23, ART13; Local Analysis SKL33 (1C `1cv8.exe`), teh130 і TEH94
  (Homag `LicenseServer.exe`); Hash Exception DVL58.
- `tests/smoke_test.py` — пройдено.

## Відкрите

- Перший бойовий звіт — завтра о 09:30 (lookback 25 год).
- Кілька алертів — блокування робочого ПЗ (1C, Homag LicenseServer, Graphtec Cutting Master):
  потрібні exceptions у Cortex, інакше в цехах не працюють програми.
- `config.json` на mdlwr01 має права `644 root` — тепер у ньому ще й ключ Cortex; варто `640 root:qmiddleware`.
- Термін дії ключа Cortex — стежити й міняти до спливу; новий ключ → лише `cortex_xdr_api_key[_id]` у config.json.
