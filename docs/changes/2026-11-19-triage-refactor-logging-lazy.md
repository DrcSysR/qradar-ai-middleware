# Тріаж Cortex: розбір одного інциденту винесено у функції, логування — лише з main()

Підготовка до спільної черги офенсів QRadar і кейсів Cortex (крок 1 з 3, поведінка не змінюється).

- `cortex_incident_triage.py`: тіло циклу `run_triage` розбите на `evaluate_incident()` (алерти + правило) і `close_incident()` (закриття/dry-run). Логіка, повідомлення логу й порядок дій ті самі.
- `cortex_xdr_scan.py`, `cortex_incident_triage.py`, `cortex_endpoint_cleanup.py`: `logging.basicConfig(FileHandler)` перенесено з рівня модуля в `setup_logging()`, що викликається з `main()`. Раніше імпорт відкривав root-власний лог і ламав би імпорт з-під qmiddleware.
- Перевірка: dry-run тріажу на mdlwr01 до/після дає однаковий набір рядків (102 інциденти, 71 would_close, 31 assigned_ours).
