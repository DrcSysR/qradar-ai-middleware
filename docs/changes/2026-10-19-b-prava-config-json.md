# 2026-10-19 (b) — права на config.json і його копії; autoupdate тримає їх щоцикл

**Статус:** зроблено. **Прод:** так (mdlwr01).

## Навіщо

`/opt/qradar-middleware/config.json` мав права `644 root:root` — будь-який користувач на
mdlwr01 міг прочитати токен QRadar (SEC), webhook Google Chat, а з 19.10 ще й ключ Cortex XDR API.
Дев'ять ручних копій поруч (`config.json.bak-*`, `.bad`, `.bak.llm01`) — так само `644`.

## Що змінено

1. Вручну на mdlwr01: `config.json` → `640 root:qmiddleware` (сервіс, поллер і воркер працюють
   від `qmiddleware`; `botnet_scan`, `cortex_xdr_scan` і cron — від root). Копії `config.json.*` →
   `600 root:root`. Перевірено: `qmiddleware` читає, `nobody` — ні, сервіс відповідає (HTTP 200).
2. `autoupdate.sh`: новий крок 0 (до `git fetch`, щоцикл) — якщо права на `config.json` не
   `640 root:qmiddleware` або на будь-якій `config.json.*` не `600 root`, виправляє й пише в лог
   `🔒 …`. Так ручна копія через `cp` без `-p` не лишиться відкритою довше ніж до наступного
   циклу (≤10 хв). Сам autoupdate копій конфігу не робить — їх робили вручну.

## Перевірка

- `bash -n autoupdate.sh` — ок; крок прогнано на тестових файлах з `644` — обидва виправлені, у лог по рядку.
