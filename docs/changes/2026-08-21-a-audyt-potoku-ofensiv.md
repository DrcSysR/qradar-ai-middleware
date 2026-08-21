# 2026-08-21 — аудит потоку офенсів і тріаж 10 нерозібраних

**Тип:** аудит · **Скоуп:** mdlwr01, QRadar (172.17.61.184) · **Прод:** так (лише читання + нотатки)

## Контекст

Запит «що по інцидентах, перевір роботу мідлваре». Перевірка стану сервісу
перетворилась на аудит потоку офенсів, бо виявилось, що сервіс здоровий, а потік —
ні.

## Що зроблено

Зміряно стан пайплайну, інвентаризовано відкриті офенси, розібрано 10 офенсів, які
ніхто не тріажив.

**Пропускна здатність.** 3658 офенсів за 10 год (≈8.5 тис./добу), 9192 закритих за
24 год. З них ~92% — `close_on_empty` (AQL після benign-фільтра порожній).
Поллер вибивав ліміт 100/ран 15 разів за день (17–20.08 — по 71–97 разів на добу).
Черга спорожнялась о 07:35, далі бізнес-ранок її забивав.

**Інвентар.** 28 449 відкритих офенсів, **0 призначених**, 985 з magnitude ≥6.
Свіжих за 7 днів — 1018. У вікні 48 год: 585 відкритих, з них 569 ніколи не
тріажились (16 — реопени вже обробленого).

**Джерело потоку.** За контрольну годину радар створив 573 офенси, з них 470 (82%)
з описом «Traffic End». По правилах-учасниках: **UC-07-1 — 379/год (rule id 100533),
UC-05-1 — 90/год (rule id 100512)**. Тобто вся проблема пропускної здатності — два
monitoring-правила, а мідлваре працює їх збирачем смiття.

**Покриття.** ~19.3 тис. із 28.5 тис. відкритих (68%) — типи, які мідлваре вміє
тріажити, але вони поза 48-год вікном. Найбільші непокриті: IRC Connections (1602),
Session Denied (1313), File Decode or Download followed by Suspicious Activity (1117),
Suspicious Activity Followed by Endpoint Administration task (746), Reset Both (645),
URL Filtering (488), Login failure to an expired account (440),
UC-ME Tor software detected (249), Suspicious Web Server Activities (232),
**Potential Exfiltration of Stored Credentials from Browsers (207)**,
Service Binary Path Changed → User/Group Added (191).

**Тріаж 10 офенсів** (усі — вузькі AQL по межах офенсу, не через мідлваре):

| Офенс | Ціль | Вердикт |
|---|---|---|
| 1234628 | mng180 / 172.17.99.177, serhiy.melnyk | **FP.** Інжект = `AdskAccessServiceHost.exe` → власні компоненти Autodesk. «C2 beaconing» = Windows Update Delivery Optimization: `UserAgent=Microsoft-Delivery-Optimization/10.0`, cleartext HTTP на 193.57.46.213/.231 (A-Systems Sp. z o.o. / 1-IX, Польща), Rx ≫ Tx. `sc.exe` — супутник апдейту |
| 1234541 | SAL62 / 172.17.101.130, viktoriia.tokareva | **FP** втричі: `dwm.exe`→`csrss.exe` під `DWM-6`; «service binary path + user/group added» = GPO-перейменування адміна (в офенсі є `Group Security Policy Applied`); X-Force Risky IP = 94.153.123.243/.201, відомий фід-FP |
| 1228055 | CNS141, «Detection of Turla Registry IOC» | **FP.** Sysmon EventID 13: `OneDrive.Sync.Service.exe` пише `HKU\…_Classes\msonedrivesyncserviceclient\shell\open\command\(Default)` (RuleName T1042) і `sdbinst.exe` пише AppCompatFlags\SdbUpdates. Обидва — легітимні компоненти Microsoft |
| 1230515, 1230514 | DEV-OAE, IIS-BX, «Access Token Abuse» | **FP.** `USR1CV8` (сервісний акаунт 1С), Logon Type 5, `services.exe`, src=dst=localhost, обидва сервери в ту саму секунду 18:15:57 — плановий рестарт служби 1С |
| 1234609, 1234396, 1235143 | 172.17.107.9 / .105.189 / .104.178, «Tor software detected» | **Не Tor.** Правило спрацьовує на DNS-запит: `client 172.17.107.9 (google.com.onion): query: google.com.onion IN A`. Реального Tor-трафіку немає (жодного порту 9001/9030/9050, лише HTTP до Akamai/CloudFront/Cloudflare/Google). Правило DNS-only — справжній Tor ним не виявиться |
| 1236169 | 209.240.111.185 → 212.1.103.128–140:5060 | **Зовнішня рекогносцировка.** SIPVicious, розгортка нашого публічного діапазону по SIP, 10 подій за секунду. Джерело — TurnKey Internet (US VPS), `209-240-111-185.static.as40244.net` |
| 1234282 | andrii.ivanytskyi | **FP.** Logon Type 3 з робочої станції 172.17.98.81 та серверної підсітки на XDC02/04/05, srv05, pdm01, srvdbapp02, V-SRV11 — типовий доступ користувача до багатьох серверів |

**Перевірена гіпотеза, що не підтвердилась.** Припущення, що Delivery Optimization
живить потік UC-07-1, зміряне і **відкинуте**: за годину 582 події з DO-агентом
проти 122 216 усього cleartext HTTP (0.5%).

## Root cause

Потік офенсів — не дефект мідлваре, а конфігурація двох правил QRadar: вони
створюють окремий офенс на сесію замість коалесценсу, і фільтр benign живе не в
тестах правила, а в AQL мідлваре (тобто після того, як офенс уже створено).

## Як перевірено

- `systemctl status`, `journalctl -u qradar-middleware`, `poller.log` — сервіс up,
  прод на коміті `6aff4e6`, каскад llm01→Vertex працює (офенс 1238449: tier-1 0.7 →
  tier-2 0.2 `mitigated`), FP-cleanup реально знімає блоки (`87.58.201.133` видалено
  з `ME-PA-Suspicious-IP-Addresses`).
- Вибірка закритих офенсів через `/siem/offenses/{id}` — статус `CLOSED`
  підтверджено, тобто закриття доїжджають до радара.
- Побічні джоби: botnet_scan 09:16 (додав 20 IP), falcon_pua 09:00 (raw=122,
  нового 0), cdn_allowlist 06:30 (22 292 IP).
- Усі вердикти тріажу — з payload'ів подій (Sysmon EventID 8/13, LEEF Palo Alto,
  BIND query log), не з висновків моделі.

## Ризики і відкат

Аудит read-only. Manual-запуски мідлваре дописали нотатки в офенси 1234628 і
1234541 («No events found») — не закривали й не призначали, відкат не потрібен.

## Лишилось відкритим

1. **Тюнінг UC-07-1 / UC-05-1 у QRadar** (веб-консоль, не репо): перенести App-ID
   whitelist з `queries/uc07_protocols.aql` у тести правила; увімкнути коалесценс
   офенсів по Source IP на 86400 с; поставити «set or replace the name of the
   associated offense», щоб офенс не називався «Traffic End». REST API тести правил
   не віддає — редагувати руками.
2. Рішення по блокуванню 209.240.111.185 (SIPVicious) — не робилось.
3. Рішення по `google.com.onion`: три хости за день, джерело запиту не встановлене.
4. Композитні офенси (одна лінза) і мутація опису офенсу — потребують рішення про
   архітектуру матчингу, кодом наосліп не правиться.
5. Backfill ~19.3 тис. відкритих офенсів покритих типів — окремим прогоном.
6. Ключі `prompts.json` під непокриті типи, першими — Tor і Credential Exfil.

## Оновлено в state.md

Розділи 3 (механізми, побічні джоби), 6 (процедури), 7 (проблеми і борг) — створені
разом із baseline.
