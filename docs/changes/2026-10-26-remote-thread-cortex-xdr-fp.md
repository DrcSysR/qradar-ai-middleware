# 2026-10-26 — лінза remote_thread_injection: агент Cortex XDR та інші відомі інжектори більше не дають «Confirmed Credential Access»

## Що було

На аналітика (`sergii.legerko`) за 07–23.10 назбиралося **157 відкритих офенсів**. Усі
переглянуто вручну за сирими подіями Sysmon EventID 8 та телеметрією Cortex XDR. Реальної
компрометації не знайдено.

| Група | Офенсів | Що це |
|---|---|---|
| Агент Cortex XDR: `cyserver.exe` → `lsass.exe`/`svchost.exe`, `cortex-xdr-payload.exe`, `VAScanner.exe` | 137 | EDR, розгорнутий 12.10 на ~650 хостів |
| `UnInstDaemon.exe` з `%TEMP%\bwp<GUID>\` | 6 | Microsoft Bing Wallpaper (підпис Microsoft за Cortex, задача `--daily-app-recovery`) |
| `esif_assist_64.exe` з `C:\Windows\Temp\DPTF\` | 4 | драйвер Intel DPTF, ~30 ноутбуків |
| Opera / Opera GX, eDrawings `EModelViewer.exe`, MasterD `DECLPLUS.EXE` | 4 | пісочниця браузера / переглядач SOLIDWORKS / ПЗ звітності |
| інше (CNS53, MNG104, перебір на GP-порталі, довгоживучий XDC02) | 6 | FP / Non-Issue, деталі в нотатках офенсів |

Причина: в AQL лінзи не було фільтра для агента Cortex XDR. FIRST CHECK промпта вважав
будь-який небезпечний інжектор у `lsass.exe` компрометацією (0.95). Через composite-офенси
(до 3 лінз) ті самі рядки потрапляли й в офенси з іншими описами: «UC-02-1 Botnet»,
«UC-06-1», «Excessive Firewall Denies», «Service Binary Path Changed…».

Офенси закрито вручну 26.10: 153 з причиною *False-Positive, Tuned*, 4 з причиною *Non-Issue*.
Кожен має нотатку з поясненням.

## Що змінено

**`queries/remote_thread_injection.aql`** — у префільтр додано пари, кожна прив'язана до
шляху, захищеного від запису користувачем:
- `cyserver.exe` з `Program Files\Palo Alto Networks\Traps`;
- `cortex-xdr-payload.exe` і `VAScanner.exe` з `ProgramData\Cyvera\LocalSystem` (ACL агента);
- `EModelViewer.exe` з `Program Files\…\eDrawings`;
- `opera.exe` з `AppData\Local\Programs\Opera*` — лише при цілі `unknown process`, як уже
  зроблено для Chrome/Edge.

**`prompts/remote_thread_injection.md`**:
- FIRST CHECK для `lsass.exe`: безпечних інжекторів тепер два, Sysmon і `cyserver.exe` зі
  шляху Traps. Обидва відфільтровані в AQL. `cyserver.exe` з будь-якого іншого місця
  вважається маскуванням.
- Новий блок **KNOWN EXCEPTIONS to the untrusted-path rule** для того, що живе в
  каталогах із правом запису для користувача і тому НЕ фільтрується в AQL. Виняток спрацьовує
  лише при збігу імені, форми шляху й цілі одночасно:
  - Bing Wallpaper `UnInstDaemon.exe` у `Temp\bwp<GUID>`;
  - Intel DPTF `esif_assist_64.exe` у `C:\Windows\Temp\DPTF`;
  - eDrawings у `Temp\EMO*`;
  - MasterD у `C:\MasterD\MD-Declaration`;
  - Opera.

## Перевірка

- Новий набір фільтрів прогнано по всіх подіях CreateRemoteThread за добу (без INOFFENSE).
  Запит виконується, Cortex і Opera з видачі зникли. Інше легітимне ПЗ лишилось видимим, як і
  планувалось.
- `tests/smoke_test.py` — OK.

## Що лишилось

- Високий фон CreateRemoteThread від штатного ПЗ (GlobalProtect HIP, `userinit`, 1С, OCS,
  Acrobat) на CRE-правилах консолі. Офенсів він не плодить, бо LLM оцінює його як безпечний,
  але це кандидати на BB-виключення в самому правилі QRadar, щоб зменшити обсяг подій.
