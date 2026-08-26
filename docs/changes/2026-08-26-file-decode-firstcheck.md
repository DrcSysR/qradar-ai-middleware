# 2026-08-26 — File Decode: FIRST CHECK, читання доказів і розширений бенін-фільтр

## Контекст
Продовження триажу офенсів, ескальованих на аналітика. Після топ-4 (UC-06-1) лишився кластер із **7 офенсів** правила «File Decode or Download followed by Suspicious Activity», усі з дефолтним `SUSPICIOUS` 0.7–0.75 і generic-поясненням: 1254976 (SKL05), 1253990 (mng170), 1253743 (REF12), 1253534 (MNG211), 1250513 (cns130), 1249835 (smq48), 1248827 (CNS131).

Правило — CRE-композит із Sysmon EventID 1 (Process Create) + 13 (Registry Set) під `User=SYSTEM`. Витяг сирих подій (`raw3.py` на mdlwr01, `INOFFENSE` + payload) дав повний перелік процесів.

## Що це насправді
- **`NetRegSrv.exe` — SOLIDWORKS PDM** (`C:\Program Files\SOLIDWORKS Corp\SOLIDWORKS PDM\NetRegSrv.exe`), разом із `AddInRegSrv32/64.exe`. Реєструє .NET-COM CLSID (`InprocServer32` = `mscoree.dll`, або `Dispatch.dll` з профілю користувача) у кущі кожного юзера при логоні — десятки RegistryEvent за раз. Модель називала його «unidentified process» і на цьому ставила 0.7.
- **`sdbinst.exe`** пише `AppCompatFlags\SdbUpdates\sysmain.sdb` / `msimain.sdb` після кумулятивного оновлення.
- **`Microsoft.Data.UsageAndQualityInsights.MaintenanceTask.exe`** зі svchost — погодинна каденція (00:12/01:13/02:14…).
- **`RUNDLL32.exe` із System32** пише `Software\Microsoft\Workspaces\Feeds\{...}\Publisher` = `Work Resources` — оновлення RemoteApp/RDS-фіда.
- **`__PSScriptPolicyTest_*.ps1`** у Temp від `sdiagnhost.exe` — AMSI script-policy проба при старті PowerShell, не дроп скрипта.
- Решта — `Explorer.EXE`/`svchost.exe` по кущу користувача (NotifyIconSettings, NetworkList, Compatibility Assistant, FileExts) і OneDrive protocol handler.

## Решта 5 офенсів (сирі події, перевірено окремо)
- **1254976 SKL05** — `powershell.exe` створює `czqzh2p3.dll` у Temp (артефакт .NET-компіляції) + оновлювач WPS Office (`ksolaunch /wpsupdate` зі svchost-таски).
- **1253990 mng170** — OneDrive (updater→Sync.Service→Launcher, protocol handler), `Explorer.EXE`, `sdbinst`, `RUNDLL32` Workspaces Feeds, CSFalcon, Windows Terminal `OpenConsole`.
- **1253743 REF12** — `__PSScriptPolicyTest_*.ps1` від powershell, AMD Radeon `cncmd.exe`, OneDrive protocol handler.
- **1253534 MNG211** — AutoCAD LT 2027 `AcCoreConsole.exe` (8 записів у `appdatalow\Autodesk`) + `AcEventSync.exe`, OneDrive, `RUNDLL32` Feeds, Office `MSOSYNC`, CSFalcon.
- **1249835 smq48** — OneDrive, `sdbinst`, `RUNDLL32` Feeds, `opera.exe` перезаписує власний Run-ключ, оновлювач Google Chrome із `C:\Windows\SystemTemp`, CSFalcon.

Через це FIRST CHECK отримав ще дві форми: (4) PowerShell/.NET scratch-файли в Temp — `__PSScriptPolicyTest_*.ps1` і випадкові 8-символьні `*.dll`/`*.cmdline`/`*.cs`; (7) підписаний іменований застосунок, що перезаписує власний autostart (Opera, Google-апдейтер у SystemTemp, OneDrive-CLSID) — Run-ключ є знахідкою лише коли ціль непідписана, з випадковим імʼям або в Temp/Downloads/Public.

## Три системні причини хибних вердиктів
1. **`Host` — це імʼя лог-сорсу, а не роль машини.** QRadar віддає `WindowsAuthServer @ mng170.modern.org`; модель читала префікс DSM і писала «Rundll32 execution on an authentication server is highly anomalous». mng170/SKL05 — звичайні робочі станції.
2. **`Proc_Path` порожній майже для всіх RegistryEvent** — Sysmon не мапить цю властивість на записи в реєстр. Модель читала порожню колонку як «unknown path» → «rundll32 from an unknown path» → 0.75. Порожній шлях ≠ user-writable шлях.
3. **Критерій «той самий процес на кількох хостах»** спрацьовував на корпоративному софті: SOLIDWORKS стоїть на всіх конструкторських машинах за дизайном.

## Зміна
`prompts/ransomware_behavior.md`:
- новий блок «How to read the evidence» — обидві пастки вище описані явно (лог-сорс ≠ роль хоста; порожній `Proc_Path` не ескалює);
- **FIRST CHECK** із 6 іменованих бенін-форм (SOLIDWORKS PDM COM-реєстрація, Windows servicing/AppCompat, RemoteApp Workspaces feed, `__PSScriptPolicyTest_*.ps1`, shell/profile bookkeeping, OneDrive protocol handler) + вайтліст вердиктів `Benign_Software_Maintenance` / `Benign_System_Activity`; попередній path-блок став SECOND CHECK;
- критерій «several hosts» звужено до «невідомий процес І user-writable шлях»;
- бенд 0.7–0.8 отримав заборону парковки: незнайомий вендорський бінарник під `C:\Program Files` із кількома подіями — це 0.4–0.6.

`queries/ransomware_behavior.aql` — бенін-префільтр доповнено парами процес+шлях: `NetRegSrv.exe`/`AddInRegSrv*` (SOLIDWORKS), `sdbinst.exe`, `Microsoft.Data.UsageAndQualityInsights*`, `CompatTelRunner.exe` (System32). Юзкейс має `close_on_empty`, тож офенси, де лишається тільки цей фон, тепер закриваються самі на 0.0.

## Дія по офенсах
7 офенсів кластера закрито як «False-Positive, Tuned» (reason_id=2) з нотаткою-розшифровкою. Разом із ними закрито 2 DNS-офенси, що висіли OPEN через ручний прогін із веб-UI: **1245527** (8.8.8.8, `DNS_Policy_Bypass` 0.45) і **1245571** (223.5.5.5 AliDNS, `Benign_Stray_Query` 0.3) — вердикти правильні, `app.py` не закриває при `is_manual=true` за дизайном.

## Стан черги після триажу
Разом із кластером закрито й решту ескальованих: injection 1253730/1250343, bruteforce 1250003/1249997, 1252230 (FW-denies), 1247458 (RunDLL32 C2) — і новий **1255704** (розподілений SSH-перебір акаунта `ubuntu` по nginx2 зі 107 зовнішніх IP: усі події Bad Username / incorrect password, жодного успішного логона, 104/107 IP уже в `ME-PA-Suspicious-IP-Addresses`; 3 IP по одній спробі — нижче порогу правила). Черга `status=OPEN and assigned_to=sergii.legerko` = **0**.

## Побічне
Пастка №1 (лог-сорс `WindowsAuthServer @ host` читається як роль) — не специфічна для цього юзкейсу. Ті самі formulations («on an authentication server», «on critical infrastructure») трапляються у вердиктах інших Windows-юзкейсів; варто винести пояснення в спільний хедер промпта, коли наступного разу буде правка кількох файлів одразу.
