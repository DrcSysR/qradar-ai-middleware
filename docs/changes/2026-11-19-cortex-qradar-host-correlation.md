# 2026-11-19 — Зведення Cortex ↔ QRadar по хосту у щоденному звіті (крок 1 єдиного потоку)

Під кожним інцидентом Cortex «на перегляд» звіт 09:30 тепер показує відкриті офенси QRadar того ж хоста:
`🔗 QRadar, відкриті офенси того ж хоста: #id [mN] опис; …`. Лише читання; нічого не закриває і не змінює чергу worker
(крок 2 — спільна `work_queue` з `source='cortex'` — окремо).

- Модуль `cortex_qradar_corr.py`: QRadar REST `/siem/offenses` (`status="OPEN"`, `magnitude>=5`, оновлені за 72 год, до 5000), збіг по IP або
  короткому імені хоста (`name:endpoint_id`, `ip:ip`, `NO_HOST…:ip` у Cortex; `offense_source` у QRadar). Адреси DNS-форвардерів і
  проксі pa-vm (`cortex_xdr_pavm_dns_proxy_ips`, `cortex_xdr_dns_forwarders`) виключені зі збігу — вони стоять замість клієнта.
- `cortex_incident_triage.run_triage` повертає `corr`; `triage_lines(..., corr, config)` додає рядок; `cortex_xdr_scan` передає. Збій QRadar лише
  логується (`qradar_corr: …`), звіт іде без рядка.
- Ключі `cortex_incident_qradar_corr[_hours|_min_magnitude|_per_incident]` у `config_schema.py` (типово 72 / 5 / 3, увімкнено).

**Перший dry-run (09:18, 126 інцидентів/36 на перегляд, 1237 офенсів QRadar): збіг 8/36, але 4 з них хибні** — інциденти про DNS-запити через форвардер `xdc02` склеювались з офенсом #1248409 по самому XDC02. Додано `cortex_incident_qradar_corr_exclude` (xdc02/xdc05/xdc06/ns1; IP форвардерів і проксі й так виключені). Лишились справжні збіги (напр. srv05 ↔ «Turla URL Host IOC», #2122350).

**Обмеження.** Збіг лише за іменем/IP: Cortex-хост з ім'ям без IP не зв'яжеться з офенсом, де джерело — IP, і навпаки. Окремий запуск
`cortex_incident_triage.py` (без `cortex_xdr_scan`) рядок `🔗` не показує.
