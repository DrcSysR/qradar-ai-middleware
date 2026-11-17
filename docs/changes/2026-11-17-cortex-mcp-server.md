# 2026-11-17 — Cortex MCP Server на mdlwr01 (read-only, для розбору інцидентів у Claude Code)

**Статус:** встановлено й перевірено (handshake + 12 інструментів + читальний запит повернув 413 інцидентів).

## Що

Пакет `cortex-mcp` (zip з консолі Cortex: Settings → Integrations → Cortex MCP Server, v1.0.5) на mdlwr01 у `/opt/cortex-mcp`:
`app/` (код), `venv/` (Python 3.13.18 через uv, лише для цього сервера; системний Python 3.11 і venv мідлвару не чіпали),
`tools/` (uv + poetry), `.env` (600, власник системного користувача `cortexmcp`, без shell). Docker не використовується.

Ключ — окремий **Standard** + роль Viewer (read-only), Bitwarden `API: Cortex Standart Viewer (MCP)` (поля `Key`, `ID`).
Наші старі ключі Advanced дають для цього сервера 401 (він шле ключ як є, без підпису).

Інструменти (лише читання): get_cases, get_issues, get_script, get_playbook, get_correlation_rules,
get_filtered_endpoints, get_assets, get_asset_by_id, get_vulnerabilities, get_assessment_profile_results,
get_tenant_info, get_audit_management_log.

## Підключення клієнта

Claude Code на машині sysr, scope user: `claude mcp add --scope user cortex -- ssh -T mdlwr01 "runuser -u cortexmcp -- sh -c '… exec /opt/cortex-mcp/venv/bin/python src/main.py'"`
(stdio через SSH; `.env` підвантажується на стороні mdlwr01, ключ на машині sysr не зберігається).

## Оновлення / обслуговування

`cd /opt/cortex-mcp/app && runuser -u cortexmcp -- env PATH=/opt/cortex-mcp/venv/bin:$PATH python src/cli.py update` — підтягує
remote_components від Cortex. Новий zip з консолі розпакувати в `app/` поверх (`.env` лишити). Ротація ключа — нове значення
в Bitwarden і в `/opt/cortex-mcp/.env`.
