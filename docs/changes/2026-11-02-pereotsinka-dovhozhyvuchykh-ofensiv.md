# 2026-11-02 — Фаза 2 поллера: переоцінка довгоживучих офенсів + розбір 22 mag-7

## Що знайшов аудит

Знімок 02.11.2026 ~14:00 (QRadar API, стеля 5000 на вибірку): 22 OPEN офенси з magnitude 7,
створені 21.09–21.10, **оновлювались того ж дня**, але не мали жодної нотатки AI (або лише
`SKIPPED`). Причина структурна: discovery поллера бере лише офенси, *створені* за 48 год
(`LOOKBACK_TIME_MS`). Офенс, у який QRadar доливає події тижнями, після першого проходу (або
без нього, якщо випав у бурст) випадає з вікна назавжди; `tools/catchup.py` існує, але
запускається вручну.

Ручний розбір усіх 22 (докази: `INOFFENSE` за 45 діб — Process Create з командними
рядками, CreateRemoteThread у lsass, RegistryEvent; PA Traffic End; nginx LEEF; Cortex XDR
API) — **інциденту немає, усі 22 закрито як Non-Issue з нотаткою**:

| Група | Офенси | Що насправді |
|---|---|---|
| 17 робочих станцій (MST70, CZO32, SMQ07, BUH01, BUH08, cns95, CNS93, CNS23, solid14, teh118, TEH100, BRK11, HRD71, ETK28, buh36, lgs56, teh06, eng37) | 1545106 1508514 1505643 1481693 1474320 1465175 1465169 1465145 1457462 1457326 1456508 1454083 1452837 1451130 1450271 1446593 1435553 1431735 | lsass-thread = `cyserver.exe` (Cortex); Service Binary Path = `tedrpers-9.3.0.231` (Cortex), Edge/Chrome/Copilot ElevationService, GoogleUpdater + зміна групи через GPO; PowerShell = `C:\ProgramData\Scripts\ocs\cbcm*`, `Invoke-UptimeReboot.ps1` (Add-Type → `csc.exe` у `SystemTemp`, 629 хостів/добу), CompatTelRunner; Temp = Edge/Opera/WPS updater, DismHost, SolidWorks з `\\adm01`; «C2 beaconing» = 34.102.140.103 (Cortex cloud, правило PA «Allow Cortex Cloud») + Telegram 149.154.167.x + X-Force FP 94.153.123.x; «login from compromised host» = наслідок тегу Compromised Hosts; щоденне «оновлення» = remote-thread chrome/OcsService/msedge/PanGpHip → `<unknown process>`, dwm → csrss. Cortex XDR: 0 алертів на цих хостах за 30 днів |
| 2 сервери | 1674571 (convertTIFF 172.17.61.23, 418k подій), 1465609 (MDT01/Veeam 172.17.61.161, 403k) | хост шле mDNS/LLMNR/SSDP (224.0.0.251:5353, 224.0.0.252:5355, 239.255.255.250:1900), брандмауер **кожного** Windows-сервера логує блок (5152/5157). Лікувати в джерелі (вимкнути mDNS/LLMNR/SSDP) або виключити 224.0.0.0/4 з «Excessive Firewall Denies» |
| 2 зовнішні | 1610785 (195.164.49.73 = `skanowanie.cert.pl`, CERT Polska, AS8308), 1492840 (45.87.91.207, Astra-net Львів) | CERT.PL з 15.10 сканує наші публічні IP (SQLi, traversal, Log4Shell, SSRF `?dest=…oast.me`), запити доходять до nginx3 (400/414/301), у `ME-PA-Suspicious-IP-Addresses` IP немає; **рішення 02.11: не блокуємо**. 45.87.91.207 = POS **GS-SCO-005**, `Go-http-client` опитує `/v1/suppa/data/production/pos/GS-SCO-005/env/_update` — правило «Potential Website Content Update» спрацьовує на `_update` |

Побічне, не закрите: **172.17.61.141 (`WIN-8PE2MNS2976`)** приймає WinRM (5985, UA
«Microsoft WinRM Client») від кожного VPN-користувача і 192.168.17.x — 4–21 тис. сесій на
день з машини, `wsmprovhost` при цьому не стартує; хоста немає в OCS, через guest agent у
PVE не знайшовся. Що це і який компонент на робочих станціях до нього ходить — з'ясувати.
На MDT01 досі працює `CSFalconService`.

## Що змінено в коді

`poller.py` — **фаза 2 `retriage_pass()`** після discovery:

- вибірка: `OPEN ∧ start_time <= початок 48-год вікна ∧ magnitude >= poller_retriage_min_magnitude (6)
  ∧ last_updated_time за останні poller_retriage_interval_hours (24)` — тобто офенс поза вікном,
  гучний і досі росте; `sort=-magnitude`, Range 0–499;
- матч лінзи той самий (`matched_rule_key` за описом або правилом-учасником); пошкоджені
  (`offense_source=null`) і ті, що вже QUEUED/IN_PROGRESS, пропускаються;
- не частіше, ніж раз на `interval_hours` на офенс: вік вердикту — з `ai_state.db`
  (`PROCESSED.last_updated`), інакше з наймолодшої нотатки «AI Analysis» у QRadar
  (`create_time`); немає ні того, ні іншого → переоцінка одразу;
- у чергу з `force=True` (воркер → `/process-one` з `force`, який обходить «Already processed»)
  і `max_span_hours = poller_retriage_span_hours (24)` — AQL дивиться на свіжий хвіст офенсу,
  а не на всю історію (та сама причина, що в `tools/catchup.py`: `INOFFENSE` за 45 діб не
  завершується за `aql_poll_timeout_seconds`);
- стеля `poller_retriage_max_per_run` (30) на ран; `poller_retriage_enabled` вимикає фазу.

Наслідок за задумом: FP закривається вердиктом ≤0.6 і зникає з вибірки; офенс зі score >0.6
лишається аналітику й отримує свіжий вердикт щодня, поки росте. Збій фази 2 логується
`🔁 Фаза 2 впала` і не ламає discovery.

`config_schema.py` — 5 нових ключів `poller_retriage_*` з коментарем.

## Перевірка

- dry-run вибірки й рішень на проді перед пушем (read-only) — див. лог сесії;
- `tests/smoke_test.py` — реєстр конфіга звірено;
- після деплою: у `poller.log` рядок `🔁 Фаза 2 (…)` щоранку, перший ран має взяти в чергу
  довгоживучі mag≥6 без свіжого вердикту.

## Відкрито після цього запису

- тюнінг правил QRadar (окремим кроком): `<unknown process>`/dwm→csrss у remote-thread;
  `cyserver.exe`/`tedrpers` у lsass і Service Binary Path; multicast 224.0.0.0/4 у FW-denies;
  `/v1/suppa/` у Website Content Update; 34.102.140.103 у C2-beaconing;
- ідентифікувати 172.17.61.141 і клієнт WinRM на робочих станціях.
