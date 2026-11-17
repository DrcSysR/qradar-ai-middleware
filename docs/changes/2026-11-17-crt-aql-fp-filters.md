# 2026-11-17 — remote_thread_injection.aql: фільтри шуму з цілі «unknown process»

**Статус:** зроблено, AQL перевірено на QRadar (синтаксис + відсутність відфільтрованих ін'єкторів у вибірці за 2 год).

## Чому

Черга QRadar не встигала: офенси `Process Created a Thread into Another/System Process` приходили
500–900/год при дренажі ~550/год (QUEUED 2303 на 17:30, m6: 353). Майже всі закриваються як безпечні
(score 0.0–0.4). За 2 год ~3000 подій Sysmon EventID 8 мали ціль `<unknown process>` від штатного ПЗ:
`PanGpHip.exe` 1940 подій / 270 хостів, 1С 344, Acrobat/Reader 196, OCSInventory.exe 136, RustDesk 118,
userinit/LogonUI/splwow64 ~200.

## Що змінено

У `queries/remote_thread_injection.aql` — виключення за зразком Chrome/Opera: ін'єктор + його рідний
шлях (`Program Files…`, `System32`) + ціль `unknown process`. Той самий процес з Temp/AppData чи в
іменовану ціль (lsass тощо) лишається видимим. Порожній результат в авто-режимі = автозакриття
(`close_on_empty`), без запиту до моделі.

Не чіпали (лишаються на AI): `bash.exe`, `node.exe`, `claude.exe`, `cmd.exe`, `firefox.exe`,
`CSFalconService.exe`, `zabbix_agentd.exe` та рештa — потребують окремого рішення.

## Обмеження

Фільтр знімає лише навантаження на мідлварь: QRadar надалі створює ці офенси. Правило в консолі QRadar
треба виключити окремо (не робилось).
