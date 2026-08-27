# 2026-08-27 — Лід по DRT07 закрито: не компроміс, а робоча станція з Opera GX / Viber / WPS

## Контекст

З 20.08.2026 у пам'яті висів **неперевірений лід**: `DRT07.modern.org` (172.17.100.211)
тримав одночасно стек офенсів шкідливої форми — `Potential Exfiltration of Stored
Credentials from Browsers` (2418 подій), `File Decode or Download followed by Suspicious
Activity preceded by RunDLL32 Outbound Network Connection containing A process changed a
file creation time` (2491), плюс правила-учасники `Potential Mailto Ransomware Behavior`
і `Suspicious Activity Followed by Endpoint Administration Task`. Тоді жодне з цих правил
не було в `prompts.json`, тож ані модель, ані аналітик їх не бачили.

27.08.2026 хост спливає знову: офенс **1253646**, вердикт `Local_Host_Scanning_Multiport`
**0.95** («remote thread injection and widespread external scanning»). Тобто лід перестав
бути одноразовим збігом і його треба було перевірити.

## Перевірка

Спосіб — той, що записаний у самому ліді: не `INOFFENSE` (обидва офенси там відвалювались
по 2-хвилинному таймауту), а сира телеметрія по хосту з коротким вікном:

```sql
SELECT QIDNAME(qid) AS Ev, "Process Name" AS Proc, "Process Path" AS Path,
       destinationip AS Dst, destinationport AS Dport, username AS Acct, COUNT(*) AS Cnt
FROM events WHERE LOGSOURCENAME(logsourceid) ILIKE '%DRT07%'
GROUP BY Ev, Proc, Path, Dst, Dport, Acct ORDER BY Cnt DESC LIMIT 120 LAST 24 HOURS
```

## Висновок — бенін

DRT07 — звичайна робоча станція користувача `sergiy.pilkevych`. Увесь «шкідливий» стек
розкладається на встановлений софт:

- **`opera.exe` з `AppData\Local\Programs\Opera` і `Opera GX`** — сотні з'єднань на 443 до
  Google/Meta/CDN. Це і є «widespread external scanning»: fan-out браузера по CDN, а не
  сканування.
- **`wpscloudsvr.exe` (WPS Office)** — трафік на Alibaba Cloud (47.x, 8.x). Уже відома
  форма по організації.
- **`Viber.exe` / `QtWebEngineProcess.exe`** — «credential exfiltration from browsers».
- **`taskhostw.exe`, `TrustedInstaller.exe`, `updater.exe` (Google), `msedgewebview2.exe`,
  `VSSVC.exe`, `svchost.exe`** — штатне обслуговування Windows.

Жодного LOLBin у бік сирої IP, жодного незвичного батька процесу, жодного виконання з
`Temp`/`Downloads`. Вердикт 0.95 був хибним.

## Дії

- Лід закрито, пам'ять `host_drt07_untriaged_stack` переписано з «неперевірений лід» на
  «перевірено, бенін».
- Правила, через які стек лишався невидимим, тепер покриті: `RunDLL32 Outbound Network
  Connection`, `Potential Mailto Ransomware Behavior`, `File Decode or Download` вже були
  заведені раніше, а `Suspicious Activity Followed by Endpoint Administration Task` додано
  сьогодні (див. окремий запис). `Potential Exfiltration of Stored Credentials from
  Browsers` (30 відкритих офенсів) власного юзкейсу ще не має, але його CRE-події тепер
  потрапляють у нову лінзу як частина композита.

## Побічне — окремий, не пов'язаний сигнал

Подія `Failure Audit: Code integrity determined that the image hash of a file is not valid`
йде пачками не лише на DRT07 (28/добу), а й на SER33 (680) та OHO07 (552). Найімовірніше —
зламаний драйвер або DLL, а не малваря, але це справжній сигнал, який ніхто не дивився.
Окремої перевірки не робив.
