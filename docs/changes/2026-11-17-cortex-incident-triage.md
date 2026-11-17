# 2026-11-17 — Cortex XDR: автотріаж інцидентів (cortex_incident_triage.py, dry-run)

**Статус:** скрипт готовий і перевірений у dry-run на mdlwr01; бойове закриття й systemd timer НЕ ввімкнено (рішення за користувачем).

## Навіщо

З 2026-11-13 pa-vm шле журнали в Cortex, і консоль щодня наповнюється інцидентами, яких ніхто не
розбирає. На 17.11 було 384 інциденти у статусі `new`; у перших 50 понад 90 % — `Flood Detection`
(Zone Protection, critical, без хоста). Аналогічно до автозакриття mitigated-офенсів QRadar
(`mitigated: true`), закриваємо те, що не потребує людини.

## Що робить

`cortex_incident_triage.py`: `incidents/get_incidents` (статус `new`, останні 72 год) →
`incidents/get_incident_extra_data` (усі алерти) → рішення по ВСІХ алертах разом:

| Правило | Умова | Статус закриття |
|---|---|---|
| `network_noise` | усі алерти з `cortex_xdr_network_sources` (PAN NGFW) і всі відсіюються `cortex_xdr_scan.network_filter` (Zone Protection / заблокована атака ззовні) | `resolved_known_issue` |
| `mitigated` | усі алерти не мережеві й уже Prevented/Blocked; severity інциденту ≤ `cortex_incident_max_severity_mitigated` (за замовчуванням `medium`) | `resolved_threat_handled` |

Не чіпає: інцидент призначений людині, із зірочкою, з нотатками, без алертів / алерти не
завантажились чи обрізані, DNS-malware з внутрішнім ініціатором, EDR Detected без блокування,
mitigated вище порога severity. Стеля `cortex_incident_max_per_run` (200).

Закриття — `incidents/update_incident` (`status` + `resolve_comment`) admin-ключем
`cortex_xdr_admin_api_key_id/_key` (потрібне право на зміну інцидентів). Журнал закритого —
таблиця `cortex_incident_closed` в ai_state.db, звіт — Google Chat (webhook як у cortex_xdr_scan).

## Безпека

`cortex_incident_dry_run` = true за замовчуванням: друкує, що закрив би, нічого не пише в консоль
і БД. `--apply` / `--dry-run` / `--hours N` перекривають конфіг. Без admin-ключа apply
неможливий. Ключі `cortex_incident_*` додано в `config_schema.py`.

## Результат dry-run (17.11 ~17:20, 72 год)

Було б закрито: `Flood Detection` / `Scan Detection` (Zone Protection) і один mitigated-інцидент
#320 (PowerShell, severity high) — його видно в журналі dry-run, після чого поріг mitigated знижено
до `medium`: obfuscated PowerShell, навіть заблокований, хай бачить людина. Лишаються відкритими
`Dns-Malware` (#375, #380 — ініціатор DNS-проксі pa-vm, шукати клієнта в DNS-журналі QRadar).
Один прогін ~2 с на інцидент (запит алертів на кожен): 384 інциденти ≈ 13 хв.

## Далі (за рішенням користувача)

1. Перевірити право admin-ключа на `incidents/update_incident` одним інцидентом: `--apply --hours 1`.
2. Unit-файли готові в `systemd/cortex_incident_triage.{service,timer}` (oneshot, `TimeoutStartSec=1800`,
   таймер кожні 30 хв, `Persistent`). Встановлення на mdlwr01 (autoupdate їх не копіює):
   `cp /opt/qradar-middleware/systemd/cortex_incident_triage.* /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now cortex_incident_triage.timer`.
   Спершу залишити `cortex_incident_dry_run: true` і дивитись `journalctl -u cortex_incident_triage`; потім `false` у config.json.

## Бойове застосування 17.11 (~17:34)

Пробний `--apply --only network_noise --hours 1`: закрито 15 інцидентів `resolved_known_issue`, перевірено в
консолі (#374, #387; #380 Dns-Malware лишився `new`) — admin-ключ має право на `update_incident`.
Після цього той самий прогін по всьому залишку (`--hours 720`, стеля 200 за запуск). Прапор
`--only network_noise|mitigated` вмикає одне правило на прогін.

## Конфіг для таймера (config.json на mdlwr01, ключі мають бути в `config_schema.py` — вже є)

```json
"cortex_incident_dry_run": false,
"cortex_incident_close_network_noise": true,
"cortex_incident_close_mitigated": false,
"cortex_incident_lookback_hours": 72,
"cortex_incident_max_per_run": 200
```

`close_mitigated: false` — на перший час таймер закриває лише очевидний шум pa-vm; mitigated (Prevented/Blocked,
severity ≤ medium) вмикати окремо після перегляду dry-run.

## Увімкнено на проді 17.11 (~17:40, за дозволом користувача)

У `config.json` на mdlwr01 (бекап `config.json.bak-<ts>`, права root:qmiddleware 640 збережені):
`cortex_incident_dry_run: false`, `close_network_noise: true`, `close_mitigated: false`. Unit-файли скопійовано в
`/etc/systemd/system/`, `cortex_incident_triage.timer` увімкнено (кожні 30 хв, перший запуск 18:00). Закриває лише
правило `network_noise`; `mitigated` вимкнено до окремого рішення.

## Зміна 17.11 (~17:50): раз на добу перед звітом

Кожні 30 хв — занадто часто. Таймер тепер `OnCalendar=*-*-* 09:00:00` (за пів години до щоденного звіту
`cortex_xdr_scan` о 09:30): спершу закриваємо шум, потім у Google Chat (webhook як у cortex_xdr_scan)
іде звіт «закрито N як шум; на перегляд: M» зі списком інцидентів, що лишились відкритими, — номер-посилання
на консоль, severity, опис, хости, причина (`needs_review` тощо; до 25 рядків). Звіт шлеться, якщо
було закриття або є що переглядати; dry-run лише друкує.
