"""cortex_incident_triage.py — тріаж інцидентів консолі Cortex XDR з автозакриттям шуму й mitigated.

Навіщо: після підключення pa-vm (2026-11-13) у консолі сотнями з'являються інциденти, які
ніхто не розбирає: `Flood Detection` (Zone Protection — пороги, а не загроза), сканери
інтернету, яких pa-vm уже відрізав, та алерти, що Cortex сам заблокував. Тут та сама логіка,
що вже відсіює їх зі щоденного звіту (cortex_xdr_scan.network_filter), але з дією в консолі:

  1. `incidents/get_incidents` — інциденти у статусах `cortex_incident_statuses` (new);
  2. `incidents/get_incident_extra_data` — усі алерти інциденту;
  3. рішення ПО ВСІХ алертах разом (одна сумнівна — інцидент лишається відкритим):
       • `network_noise` — усі алерти з мережевих джерел і всі відсіюються network_filter
         (Zone Protection / заблокована атака ззовні) → `cortex_incident_status_noise`;
       • `mitigated` — усі алерти не мережеві й уже Prevented/Blocked агентом
         → `cortex_incident_status_mitigated`;
     усе інше (внутрішній ініціатор DNS-malware, незаблоковане, EDR Detected) — не чіпаємо;
  4. запобіжники: інцидент призначений людині, із зірочкою, з нотатками, без алертів чи з
     недоступними алертами, severity вище `cortex_incident_max_severity_mitigated` для
     mitigated — пропускається; стеля `cortex_incident_max_per_run`;
  5. `incidents/update_incident` (status + resolve_comment) admin-ключем, запис у таблицю
     `cortex_incident_closed` в ai_state.db, звіт у Google Chat.

Безпека за замовчуванням: `cortex_incident_dry_run` = true — скрипт лише друкує, що закрив би;
нічого не пише в консоль і в БД. `--apply` / `--dry-run` перекривають конфіг, `--hours N` —
глибину вибірки, `--only network_noise|mitigated` — лише одне правило. Без admin-ключа (`cortex_xdr_admin_api_key_id`/`_key`, роль з правом на
зміну інцидентів) apply неможливий — працює як dry-run.

Запуск вручну (поки не заведено systemd timer):
  /opt/qradar-middleware/venv/bin/python /opt/qradar-middleware/cortex_incident_triage.py --dry-run
Lock — fcntl на cortex_incident_triage.lock, лог — cortex_incident_triage.log.
Секрети (ключі, webhook) — тільки в config.json (gitignored), НЕ комітити.
"""
import fcntl
import logging
import os
import sqlite3
import sys
import time
import uuid
from collections import Counter

import requests

import cortex_xdr_scan as cx

BASE_DIR = "/opt/qradar-middleware"
DB_PATH = os.path.join(BASE_DIR, "ai_state.db")
LOCK_FILE = os.path.join(BASE_DIR, "cortex_incident_triage.lock")
LOG_FILE = os.path.join(BASE_DIR, "cortex_incident_triage.log")

PAGE = 100
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULTS = {
    "cortex_incident_dry_run": True,
    "cortex_incident_statuses": ["new"],
    "cortex_incident_lookback_hours": 72,
    "cortex_incident_max_per_run": 200,
    "cortex_incident_close_network_noise": True,
    "cortex_incident_close_mitigated": True,
    # Статуси закриття Cortex: resolved_threat_handled / resolved_known_issue /
    # resolved_duplicate / resolved_false_positive / resolved_other.
    "cortex_incident_status_noise": "resolved_known_issue",
    "cortex_incident_status_mitigated": "resolved_threat_handled",
    # mitigated закриваємо лише до цієї важливості включно (low|medium|high|critical).
    "cortex_incident_max_severity_mitigated": "medium",
    "cortex_incident_report_title": "🧹 Cortex XDR — автотріаж інцидентів",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)


def cfg(config: dict, key: str):
    if key in DEFAULTS:
        return config.get(key, DEFAULTS[key])
    return cx.cfg(config, key)


def admin_config(config: dict) -> dict | None:
    key_id = str(config.get("cortex_xdr_admin_api_key_id", "")).strip()
    key = str(config.get("cortex_xdr_admin_api_key", "")).strip()
    if not (key_id and key):
        return None
    return {**config, "cortex_xdr_api_key_id": key_id, "cortex_xdr_api_key": key}


def post(config: dict, path: str, request_data: dict, timeout: int = 60):
    """Один POST у Public API; повертає reply або None (помилку залоговано)."""
    url = f"https://{cx.api_host(config)}{path}"
    try:
        resp = requests.post(url, headers=cx.api_headers(config),
                             json={"request_data": request_data}, timeout=timeout)
    except Exception as e:
        logging.error(f"Cortex API {path}: {e}")
        return None
    if resp.status_code != 200:
        logging.error(f"Cortex API {path} HTTP {resp.status_code}: {resp.text[:300]}")
        return None
    try:
        return resp.json().get("reply")
    except ValueError:
        logging.error(f"Cortex API {path}: відповідь не JSON: {resp.text[:200]}")
        return None


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cortex_incident_closed (
                incident_id TEXT NOT NULL,
                rule TEXT NOT NULL,
                status TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                alert_count INTEGER,
                run_id TEXT,
                closed_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (incident_id, closed_ts)
            )
            """
        )


def fetch_incidents(config: dict, statuses: list, hours: float) -> list | None:
    """Усі інциденти у вказаних статусах, створені за останні `hours` год (від нових)."""
    since = int((time.time() - hours * 3600) * 1000)
    out: list = []
    frm = 0
    while True:
        reply = post(config, "/public_api/v1/incidents/get_incidents", {
            "filters": [
                {"field": "status", "operator": "in", "value": statuses},
                {"field": "creation_time", "operator": "gte", "value": since},
            ],
            "search_from": frm, "search_to": frm + PAGE,
            "sort": {"field": "creation_time", "keyword": "desc"},
        })
        if reply is None:
            return None
        batch = reply.get("incidents") or []
        out.extend(batch)
        if len(batch) < PAGE or len(out) >= int(reply.get("total_count") or 0):
            return out
        frm += PAGE


def fetch_alerts(config: dict, incident_id: str) -> list | None:
    reply = post(config, "/public_api/v1/incidents/get_incident_extra_data",
                 {"incident_id": str(incident_id), "alerts_limit": 100})
    if reply is None:
        return None
    return (reply.get("alerts") or {}).get("data") or []


def alert_item(a: dict) -> dict:
    """Поля алерту у формі, яку розуміє cx.network_filter."""
    return {"source": a.get("source") or "", "category": a.get("category") or "",
            "local_ip": a.get("action_local_ip"), "action": a.get("action_pretty") or a.get("action") or ""}


def is_mitigated(a: dict) -> bool:
    act = (a.get("action_pretty") or a.get("action") or "").lower()
    return any(w in act for w in ("prevent", "block"))


def decide(inc: dict, alerts: list | None, config: dict, net_sources: set, drop_cats: list):
    """(rule, status, why) для закриття або (None, None, причина_пропуску)."""
    if inc.get("assigned_user_mail"):
        return None, None, "assigned"
    if inc.get("starred") or inc.get("starred_manually"):
        return None, None, "starred"
    if inc.get("notes"):
        return None, None, "has_notes"
    if not alerts:
        return None, None, "no_alerts_or_api_error"
    if len(alerts) < int(inc.get("alert_count") or 0):
        return None, None, "alerts_truncated"

    keep_inbound = bool(cx.cfg(config, "cortex_xdr_network_keep_inbound_blocked"))
    if cfg(config, "cortex_incident_close_network_noise"):
        reasons = []
        for a in alerts:
            it = alert_item(a)
            r = cx.network_filter(it, net_sources, drop_cats, keep_inbound) if it["source"] in net_sources else None
            if not r:
                break
            reasons.append(r)
        else:
            return "network_noise", cfg(config, "cortex_incident_status_noise"), ",".join(sorted(set(reasons)))

    if cfg(config, "cortex_incident_close_mitigated"):
        limit = SEV_RANK.get(str(cfg(config, "cortex_incident_max_severity_mitigated")).lower(), 3)
        sev = SEV_RANK.get(str(inc.get("severity") or "").lower(), 4)
        if all(alert_item(a)["source"] not in net_sources and is_mitigated(a) for a in alerts):
            if sev <= limit:
                return "mitigated", cfg(config, "cortex_incident_status_mitigated"), "all alerts prevented/blocked"
            return None, None, f"mitigated_but_severity_{inc.get('severity')}"
    return None, None, "needs_review"


def describe(inc: dict, rule: str, status: str, why: str, alerts: list) -> str:
    names = Counter(a.get("name") for a in alerts)
    top = ", ".join(f"{n}×{c}" if c > 1 else str(n) for n, c in names.most_common(3))
    return (f"#{inc.get('incident_id')} [{inc.get('severity')}] {(inc.get('description') or '')[:70]} | "
            f"алертів {len(alerts)}: {top} | {rule} ({why}) → {status}")


def resolve(admin_cfg: dict, inc_id: str, status: str, comment: str) -> bool:
    reply = post(admin_cfg, "/public_api/v1/incidents/update_incident",
                 {"incident_id": str(inc_id), "update_data": {"status": status, "resolve_comment": comment}})
    return reply is not None


def record(rows: list, run_id: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO cortex_incident_closed "
            "(incident_id, rule, status, description, severity, alert_count, run_id) VALUES (?,?,?,?,?,?,?)",
            [(str(i.get("incident_id")), r, s, (i.get("description") or "")[:200], i.get("severity"),
              int(i.get("alert_count") or 0), run_id) for i, r, s in rows])


def build_chat_message(title: str, closed: list, kept: Counter, total: int, dry_run: bool) -> dict:
    by_rule = Counter(r for _, r, _ in closed)
    lines = [f"*{title}*" + (" (dry-run)" if dry_run else "")]
    lines.append(f"Переглянуто {total}; {'було б закрито' if dry_run else 'закрито'} {len(closed)} "
                 f"({', '.join(f'{r}: {n}' for r, n in by_rule.items()) or '—'}); "
                 f"лишилось на розбір {total - len(closed)}.")
    if kept:
        lines.append("Не закриті: " + ", ".join(f"{k}: {v}" for k, v in kept.most_common()))
    return {"text": "\n".join(lines)}


def main() -> None:
    config = cx.load_config()
    run_id = uuid.uuid4().hex[:12]
    args = sys.argv[1:]
    dry_run = bool(cfg(config, "cortex_incident_dry_run"))
    if "--apply" in args:
        dry_run = False
    if "--dry-run" in args:
        dry_run = True
    if "--only" in args:   # --only network_noise | mitigated: вимкнути інше правило на цей прогін
        only = args[args.index("--only") + 1]
        config = {**config, "cortex_incident_close_network_noise": only == "network_noise",
                  "cortex_incident_close_mitigated": only == "mitigated"}
    hours = float(cfg(config, "cortex_incident_lookback_hours"))
    if "--hours" in args:
        hours = float(args[args.index("--hours") + 1])

    if not (cx.cfg(config, "cortex_xdr_api_fqdn") and cx.cfg(config, "cortex_xdr_api_key_id")
            and cx.cfg(config, "cortex_xdr_api_key")):
        logging.error("Немає cortex_xdr_api_fqdn / cortex_xdr_api_key_id / cortex_xdr_api_key у config.json")
        sys.exit(2)
    admin_cfg = admin_config(config)
    if not dry_run and admin_cfg is None:
        logging.error("Немає cortex_xdr_admin_api_key_id / _key — закриття неможливе, запускаю як dry-run")
        dry_run = True
    webhook_url = config.get("cortex_xdr_webhook_url") or config.get("falcon_pua_webhook_url")

    lock_fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logging.warning("Previous cortex_incident_triage still running. Skipping this run.")
        sys.exit(0)

    net_sources = set(cx.cfg(config, "cortex_xdr_network_sources"))
    drop_cats = list(cx.cfg(config, "cortex_xdr_network_drop_categories"))
    statuses = list(cfg(config, "cortex_incident_statuses"))
    max_per_run = int(cfg(config, "cortex_incident_max_per_run"))
    logging.info(f"=== Cortex incident triage run_id={run_id} hours={hours:g} statuses={statuses} "
                 f"max={max_per_run}{' DRY-RUN' if dry_run else ' APPLY'} ===")

    incidents = fetch_incidents(config, statuses, hours)
    if incidents is None:
        logging.error("Cortex API недоступний — нічого не робимо")
        sys.exit(1)

    closed: list = []          # (incident, rule, status)
    kept: Counter = Counter()
    for inc in incidents:
        iid = str(inc.get("incident_id"))
        alerts = fetch_alerts(config, iid)
        rule, status, why = decide(inc, alerts, config, net_sources, drop_cats)
        if not rule:
            kept[why] += 1
            logging.info(f"keep #{iid} [{inc.get('severity')}] {(inc.get('description') or '')[:70]} — {why}")
            continue
        if len(closed) >= max_per_run:
            kept["max_per_run"] += 1
            continue
        logging.info(f"{'[dry-run] ' if dry_run else ''}close {describe(inc, rule, status, why, alerts)}")
        if not dry_run:
            comment = f"Автотріаж ({rule}): {why}. run={run_id}"
            if not resolve(admin_cfg, iid, status, comment):
                kept["update_failed"] += 1
                continue
        closed.append((inc, rule, status))

    logging.info(f"incidents={len(incidents)} {'would_close' if dry_run else 'closed'}={len(closed)} kept={dict(kept)}")
    message = build_chat_message(cfg(config, "cortex_incident_report_title"), closed, kept, len(incidents), dry_run)
    if dry_run:
        print(message["text"])
        logging.info("DRY-RUN: нічого не закрито, state і звіт не записано")
        return
    init_db()
    record(closed, run_id)
    if closed and webhook_url:
        cx.send_to_chat(webhook_url, message)


if __name__ == "__main__":
    main()
