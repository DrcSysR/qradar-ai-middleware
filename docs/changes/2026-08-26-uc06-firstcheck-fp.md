# 2026-08-26 — UC-06-1: FIRST CHECK проти хибних «multi-stage compromise»

## Контекст
Ревʼю 4 найвищих за скором офенсів, ескальованих на аналітика (sergii.legerko), показало, що **всі 4 — false positives** із верхнього бенду 0.9–1.0. Модель (Vertex fallback) бере страшні назви composite-правила UC-06-1 і за наявності будь-якого «Success Audit» / admin-логона / Temp-процесу видає `Active_Multi_Stage_Compromise` 0.9–1.0.

## Розібрані офенси (усі FP)
- **1251761** — хост `librenms`. «SNMP C2 beaconing» = SNMP-опитування (dport 161) віддалених пристроїв + check_mk(6556) + apt/snap Canonical. Штатний моніторинг.
- **1254567** — хост `XDC05` (контролер домену). «Compromised DC» = DC валідує креденшели нормальних юзерів + службові palo.alto/nextcloud + Group Policy; «DGA» = DC як DNS-forwarder. Реальної зміни привілейованих груп немає.
- **1254561** — реальний хост `SMQ44` (asset «BUH03» застарів, атрибуція помилкова). «MOVEit exploit» = powershell `*.cmdline` у Temp (артефакт .NET-компіляції); «process from Temp» = `DismHost.exe` (Windows servicing); зміна акаунта/групи = SYSTEM(0x3E7) торкнувся локального admin RID-500 — 0 подій 4732/4720/4724, ескалації немає.
- **1248351** — хост `win-8pe2mns2976` = McAfee/Trellix NSP Manager (security appliance). 28k McAfee-повідомлень + generic NSP alerts + логони до власної адмінконсолі.

## Зміна
`prompts/67500653.md` (UC-06-1) — додано блок **FIRST CHECK** із 5 формами, які МУСЯТЬ отримати 0.0–0.3 `Contained_False_Correlation`, навіть якщо патерн «успішний компроміс + пост-активність» виглядає виконаним:
1. Моніторинг/SNMP-хости (librenms/zabbix/... , dport 161/6556) — не C2.
2. Контролер домену за роботою (валідація креденшелів, службові логони, GPO) + DGA на DNS-резолвері — не компроміс.
3. Windows servicing / .NET-компіляція (`*.cmdline` у Temp від powershell/csc; DismHost/TiWorker/TrustedInstaller з Temp\GUID) — не exploit.
4. SYSTEM(0x3E7) property-touch локального акаунта (4738/4735) БЕЗ member-add(4732/4728/4756)/create(4720)/pwreset(4724) від non-SYSTEM логону — LAPS/GPO, не ескалація.
5. Security-appliance (McAfee/Trellix NSP Manager, generic NSP alerts, WinCollect) із self-alerts — не компроміс.

Рубрику 0.9–1.0 звужено: тепер вимагає, щоб ЖОДЕН FIRST CHECK не спрацював І був реальний member-add привілейованої групи / реальний C2 (не SNMP-полінг).

## Дія по офенсах
4 офенси закрито як «False-Positive, Tuned» (reason_id=2) з нотаткою-розшифровкою (виконано вручну через auto-mode класифікатор блокує close з боку middleware-хоста).

## Побічне
- QRadar asset для `172.17.99.20` застарів (SMQ44 показується як BUH03) — варто оновити asset-модель, інакше атрибуція офенсів на цій IP хибна.
