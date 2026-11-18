# 2026-11-18 — QRadar: чистка мертвих log source'ів (група 1)

**Що зроблено:** видалено **362** log source'и з 1733 на консолі `qr-aio` (172.17.61.184), через `tools/qradar_logsource_cleanup.py`.

**Відбір (аналіз 2026-11-18):** статус `ERROR`, остання подія > 90 днів тому, жодної події за 7 днів (AQL `GROUP BY logsourceid LAST 7 DAYS`), і одне з:
- **дублі живих** (45): Windows-джерело з тим ж хостом і типом, що має події (різниця лише `host` / `host.modern.org`) — 32 Windows + 13 інших;
- **станції, яких немає** (317): `WindowsAuthServer @ <host>` — хоста немає в Cortex (`get_endpoint`, 914 записів) або `last_seen` > 15 дн, **і** немає DNS-запису `<host>.modern.org`.
Живу перевірку скрипт повторює перед кожним видаленням (статус ERROR/DISABLED, вік ≥ 90 д).

**Не видалялось (лишилось у списку на рішення):**
- 163 станції без подій 90+ днів, яких немає в Cortex, але імена ще резолвляться в DNS (напр. ADM00 172.17.61.4) — або вимкнені, або застарілі DNS-записи;
- 24 вимкнені (DISABLED);
- 97 «живих» джерел, що перестали слати: Linux/pfSense/Apache/NGINX/BIND (pve01–15, nginx0/1, git, sp, nas-*, ns1…) — **остання подія 14–15.05.2026**; їхніх власних подій у QRadar зараз немає (перевірено для pve01, nginx0) → прогалина покриття, не чистка; 3Com/HP-комутатори — 19.03–09.04.2026.

**Результат (знімок `tools/qradar_upgrade_check.py`):** log source'ів у `ERROR` 918 → 530; `SUCCESS` 783 → 809; активних джерел за 15 хв 724 → 764; потік подій без змін (937 тис. → 933 тис. за 15 хв). Правила та reference sets без змін.

**Відкат:** повні визначення видалених log source'ів — `/opt/qradar-middleware/logsource_cleanup_backup_20261118_094947.json` (mdlwr01); хід — `logsource_cleanup.log`. Для WindowsAuthServer/Linux QRadar сам створить log source, коли пристрій знову надішле події.

**Нотатка по API:** `DELETE …/log_source_management/log_sources/{id}` повертає HTTP 406 на `Accept: application/json` — потрібен `Accept: text/plain` (204 при успіху); виправлено в скрипті.

**Відкриті:** розслідувати зникнення Linux-джерел 15.05.2026 (rsyslog / relay `api-gw` / фаєрвол); вирішити групу 2 (163) і вимкнені (24).
