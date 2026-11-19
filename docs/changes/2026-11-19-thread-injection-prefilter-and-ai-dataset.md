# 2026-11-19 — Thread-injection: розвантаження tier-1 + журнал навчальних прикладів

## Вимірювання (llm01, 3 год, 1073 запити)
- Запит у середньому 20,6 с (p90 33,6 с): обробка промпту 8,2 с (40%), генерація 12,4 с (60%, ~52 токени, 3–7 ток/с).
- Промпт: середнє 1160 токенів, медіана 796, макс. 4886.
- 24 год: 4815 вердиктів Thread_Injection, жоден вище 0,4 (Benign 0,0–0,3: 2695; Unusual 0,4: 2120) — модель на цьому правилі завжди повертала «закрити».
- Зріз після наявних фільтрів (6 год): майже всі рядки мають ціль `unknown process` — Sysmon не резолвить ціль, аналізувати нема чого.

## Зміни
1. `queries/remote_thread_injection.aql`: ще 15 AND NOT-блоків «ціль unknown process + ін'єктор у рідному каталозі» (cmd/powershell/CompatTelRunner/gpscript/mstsc/msiexec/igfxCUIService зі System32; Git bash; node; py; PyCharm; claude; OneScript; Firefox; Zabbix; Adobe ARM/acrobat_sl; PanGPS; SolidWorks; Chrome notification_helper; BlueStacks; Biesse erl). Той самий бінарник з іншого шляху і будь-яка названа ціль лишаються видимими. `CSFalconService.exe` навмисно не фільтрується (Falcon виводиться). Перевірка на живих даних, вікно 6 год: подій 7459 → 2295 (−69%); `chrome→cmd.exe`, `wscript→cmd.exe` лишились.
2. `ai_dataset.py` + хук у `app.py::process_one`: кожен розбір, що дійшов до моделі, пишеться в окремий `/opt/qradar-middleware/ai_dataset.db` (таблиця `ai_dataset`): точний промпт (zlib), вердикт/score/пояснення tier-1, ескалація, фінальний вердикт; `human_outcome` — NULL (заповнюється окремо). Кільцевий буфер `ai_dataset_max_rows` (150000). Збій запису лише WARNING, обробку не ламає. Ключі `ai_dataset_enabled`, `ai_dataset_max_rows` у `config_schema.py`.

## Як перевірити
- Кількість викликів моделі за добу до/після: `journalctl -u qradar-middleware | grep -c оброблено` (до: ~8–9 тис./добу з Thread_Injection ≈ 4,8 тис.).
- `sqlite3 ai_dataset.db "select count(*), avg(prompt_chars) from ai_dataset"`.
- Ризик: фільтр прибирає з огляду моделі нерозпізнані цілі зі штатних каталогів; якщо потрібна глибша перевірка — зняти відповідний AND NOT.

## Не зроблено (наступні кроки)
Заповнення `human_outcome` (повторне відкриття офенсу), скорочення JSON-відповіді, ручний контрольний набір, дистиляція меншої моделі.
