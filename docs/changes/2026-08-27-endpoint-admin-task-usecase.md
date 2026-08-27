# 2026-08-27 — Юзкейс «Suspicious Activity Followed by Endpoint Administration Task»

## Контекст

Зріз по відкритих офенсах на 27.08.2026: **1663 OPEN**, з них **943 (57%) не матчаться в
`prompts.json` взагалі** — правило не покрите, тож ані модель, ані аналітик їх ніколи не
бачили. Вибірка на 150 офенсах: 86% відкритих не мають жодної нотатки «AI Analysis».

Найбільший бакет — **641 офенс** на IBM-івському поведінковому правилі
`Suspicious Activity Followed by Endpoint Administration Task` (rule 133844 SYSTEM +
134474 OVERRIDE). Це третина всієї відкритої черги.

## Що це насправді

Рівно **один офенс на хост**, по всьому парку робочих станцій. Розподіл композитів:
481 `containing Process Create`, 122 `File Delete Detected`, решта — RegistryEvent /
Network connection / FileCreate. Правило-учасник збігається саме з собою у 640 випадках;
поруч трапляються `Potential Exfiltration of Stored Credentials from Browsers` (30) і
`Suspicious Activity Followed by Potential Initial Access Task` (14).

Заміряний зріз CRE-подій за 3 доби показав чистий інвентар штатного софту: OneDrive,
WPS Office (ksolaunch/chromelauncher), 1С, Chrome/Opera/Edge, AMD Radeon, HP Support
Assistant, Xerox/Epson, Autodesk, SOLIDWORKS PDM, Adobe, LibreOffice, CrowdStrike,
Cortex XDR, Viber, сервісні таски System32, PhoneExperienceHost, Windows Terminal,
GlobalProtect. **Жодного істинного спрацювання не знайдено.**

## Зміна

Новий юзкейс без правок коду: ключ у `prompts.json` + `prompts/endpoint_admin_task.md` +
`queries/endpoint_admin_task.aql`, з прапорцем `close_on_empty`.

Ключ — `"Suspicious Activity Followed by Endpoint Administration"` (без хвоста
`task`/`Task`), бо опис офенсу пише з малої, а назва правила — з великої. Стоїть
передостаннім, перед `Default`: сигнал найслабший, тому в композиті має програвати
будь-якій конкретнішій лінзі.

### AQL — інвертована логіка фільтра

Хвіст легітимного софту тут надто довгий, щоб перелічувати його як у
`ransomware_behavior.aql`. Тому рядок лишається, тільки якщо він вартий погляду:

1. Беруться **лише CRE-події** (`LOGSOURCETYPENAME(devicetype) = 'Custom Rule Engine'`) —
   саме вони несуть `Process Name` + `Process Path`. Свідомо НЕ звужено до самої події
   `Endpoint Administration`: інакше в композиті з `Credential Exfiltration` (30 офенсів)
   `close_on_empty` закрив би офенс, а докази другого правила не побачила б жодна модель.
2. `Process Path IS NULL` — знімається цілком. Це майже весь залишок (`cmd.exe`,
   `powershell.exe` без шляху) і в ньому нема жодного доказу.
3. Лишається: **(a)** LOLBin за іменем, але поза своєю штатною домівкою (System32 /
   SysWOW64 / `Program Files\PowerShell`) — форма «системний бінар, скопійований у папку
   застосунку»; **АБО (b)** процес поза довіреними місцями встановленого софту
   (`Program Files`, 8.3-скорочення `PROGRA~`, `WindowsApps`, `SystemApps`, `System32`,
   `SysWOW64`, `servicing`, `SystemTemp`, `Microsoft.NET`, per-user інсталяції штатного
   парку — OneDrive/Edge/Teams/Google/Opera/Viber/kingsoft/MS Store/Claude/node_modules).

### Заміряний ефект фільтра

Прогін самого фільтра по організації (без `INOFFENSE`): **10–11 рядків за добу** проти
тисяч. Що вижило — саме те, що варто дивитись:

- `C:\Prima Power\NCexpress\...`, `C:\ww4\Programs\NCWEEKE.exe`, `C:\MACHINE1\Programs\...`
  — верстатний софт, який ставиться поза `Program Files` (бенін, але має бути видимий);
- `certutil.exe` у `C:\Users\<user>\AppData\Roaming\UniCryptH\` — копія системного бінара
  в теці застосунку, класична форма маскараду;
- `ncftpput.exe` з мапленого диска `K:\Work\cmd\copy2ftp\bin\` під `SQLSERVERAGENT`;
- `python.exe` з `C:\ProgramData\anaconda3`;
- `Move Mouse.exe` з `D:\install\` і `D:\MDC\` (спливло через Turla-IOC лінзу).

Перевірка на живому офенсі 1259803: 0 рядків → `close_on_empty` закриє як бенін.

### Промпт

FIRST CHECK — «софт, що живе поза Program Files за призначенням» (Prima Power, ww4,
MACHINE1, SOLIDWORKS через 8.3, батч на мапленому диску під сервісним акаунтом) →
0.1–0.3 `Benign_LOB_Software`. Ширина по хостах/акаунтах тут — доказ ЗА бенін, а не проти.

SECOND CHECK — маскарад і стейджинг: системний бінар поза System32 (0.7–0.8
`Suspicious_LOLBin_Relocated`), невідомий бінар із user-writable шляху (0.7–0.8
`Suspicious_Unknown_Binary`), знищення тіньових копій (0.9–1.0), невідомий бінар із
user-writable шляху на багатьох хостах (0.9–1.0).

Окремо в промпті зафіксовано дві особливості доказів: (1) на частині CRE-подій парсер
кладе в `Proc` логін користувача, а справжній бінар — на початок `Proc_Path` із хвостом
`User: MODERN\<login>`; (2) офенс зазвичай композитний і `Activity` називатиме інші
правила — ці рядки включені навмисно, оцінювати треба за найсильнішим.

Правило нічого не блокує, тож `mitigated` заборонено.

## Очікуваний ефект

641 офенс третини черги переходять із «ніколи не тріажені» у авто-закриття за
`close_on_empty`, а ~10 рядків на добу по організації доходять до моделі.
