"""cortex_xdr_scan.py — щоденний звіт по алертах Palo Alto Cortex XDR.

Стягує події логсорсу Cortex XDR з QRadar (за LOGSOURCENAME, не за QID — щоб
ловити і ще не змаплені на QID події), парсить CEF payload, виключає
Informational / тестові / allowlist-алерти, дедуплікує по externalId алерта
проти таблиці cortex_xdr_reported в ai_state.db і, якщо щось залишилося,
шле звіт у Google Chat через webhook.

Запускається через cron/timer (раз на добу). Lock через fcntl на cortex_xdr_scan.lock.
Конфіг — секції з префіксом `cortex_xdr_*` у /opt/qradar-middleware/config.json.
Webhook: окремий cortex_xdr_webhook_url або (fallback) спільний falcon_pua_webhook_url.

State: окрема таблиця cortex_xdr_reported в тій самій ai_state.db.
Webhook URL — тільки в config.json (gitignored), НЕ комітити в репо.

Cortex CEF (приклад):
  CEF:0|Palo Alto Networks|Cortex XDR|Cortex XDR 5.1.0|XDR Agent|<alert name>|<sev>|
      externalId=11148 shost=3D4WRQ2 suser=acme\\user cat=Restrictions
      request=https://modernexpo.xdr.eu.paloaltonetworks.com/alerts/11148
      fileHash=<sha256> act=Detected (Reported) cs1=<initiated by> cs5=<CGO CMD> ...
"""
import json
import os
import re
import sys
import time
import sqlite3
import logging
import urllib3
import fcntl
import uuid
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "ai_state.db")
LOCK_FILE = os.path.join(BASE_DIR, "cortex_xdr_scan.lock")
LOG_FILE = os.path.join(BASE_DIR, "cortex_xdr_scan.log")

# CEF severity-число -> людська мітка. Cortex мапить: Info=0, Low=3, Med=6, High=9, Crit=10.
SEV_WORDS = {
    "informational": 0, "info": 0, "low": 3, "medium": 6, "med": 6,
    "high": 9, "critical": 10, "crit": 10,
}

DEFAULTS = {
    "cortex_xdr_lookback_hours": 25,
    "cortex_xdr_dedup_days": 30,
    "cortex_xdr_aql_timeout_seconds": 300,
    "cortex_xdr_max_aql_rows": 5000,
    "cortex_xdr_max_report_items": 50,
    # Підрядок назви логсорсу Cortex у QRadar (LOGSOURCENAME ILIKE '%...%').
    # Ловить і ручний логсорс, і авто-створений "Cortex XDR @ api-gw".
    "cortex_xdr_logsource_filter": "Cortex XDR",
    # CEF-поріг важливості. Беремо тільки sev >= цього значення.
    # Шкала CEF: 0=Info, 3=Low, 6=Medium, 9=High, 10=Critical.
    # Default 3 → відсікаємо лише Informational, лишаємо Low і вище.
    "cortex_xdr_min_severity": 3,
    # Назви алертів, що завжди ігноруємо (тестові / відомі FP).
    "cortex_xdr_fp_alert_names": [
        "Example Cortex XDR Alert",
    ],
    # Окремі externalId алертів, що вже триаджено як FP.
    "cortex_xdr_fp_external_ids": [],
    "cortex_xdr_report_title": "🛡️ Cortex XDR — щоденний звіт",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)


def load_config() -> dict:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def cfg(config: dict, key: str):
    return config.get(key, DEFAULTS[key])


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cortex_xdr_reported (
                external_id TEXT NOT NULL,
                hostname TEXT,
                alert_name TEXT,
                first_reported_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_reported_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                report_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (external_id)
            )
            """
        )


_EXT_RE = re.compile(r"([A-Za-z][A-Za-z0-9_]*)=(.*?)(?=\s[A-Za-z][A-Za-z0-9_]*=|$)")


def _cef_unescape(v: str) -> str:
    # Порядок важливий: спершу екранований equals, потім подвійний backslash.
    return v.replace("\\=", "=").replace("\\\\", "\\").replace("\\n", " ").replace("\\r", "")


def parse_cef(payload: str) -> dict:
    """CEF:Ver|Vendor|Product|DevVer|SigID|Name|Severity|k=v k=v ...

    Повертає dict з ключами заголовка (vendor/product/sig_id/name/cef_severity)
    та всіма extension key=value (значення можуть містити пробіли)."""
    if not payload:
        return {}
    idx = payload.find("CEF:")
    if idx < 0:
        return {}
    cef = payload[idx:]
    # Розбиваємо заголовок по неекранованих '|' рівно на 7 (8 частин з extension).
    parts = re.split(r"(?<!\\)\|", cef, maxsplit=7)
    if len(parts) < 8:
        return {}
    out = {
        "vendor": parts[1].replace("\\|", "|").replace("\\\\", "\\"),
        "product": parts[2].replace("\\|", "|").replace("\\\\", "\\"),
        "device_version": parts[3],
        "sig_id": parts[4].replace("\\|", "|"),
        "name": parts[5].replace("\\|", "|"),
        "cef_severity": parts[6].strip(),
    }
    for k, v in _EXT_RE.findall(parts[7]):
        out[k] = _cef_unescape(v.strip())
    return out


def run_aql(qradar_api: str, headers: dict, aql: str, timeout_seconds: int) -> list:
    try:
        resp = requests.post(
            f"{qradar_api}/ariel/searches",
            headers={**headers, "Content-Type": "application/json"},
            params={"query_expression": aql},
            verify=False, timeout=30,
        )
    except Exception as e:
        logging.error(f"AQL submit error: {e}")
        return []
    if resp.status_code not in (200, 201):
        logging.error(f"AQL submit HTTP {resp.status_code}: {resp.text[:300]}")
        return []
    j = resp.json()
    sid = j.get("search_id") or j.get("cursor_id")
    if not sid:
        logging.error("AQL: empty search_id")
        return []

    waited = 0
    while waited < timeout_seconds:
        time.sleep(3)
        waited += 3
        try:
            sresp = requests.get(f"{qradar_api}/ariel/searches/{sid}",
                                 headers=headers, verify=False, timeout=15)
        except Exception as e:
            logging.error(f"AQL status error: {e}")
            return []
        if sresp.status_code != 200:
            logging.error(f"AQL status HTTP {sresp.status_code}")
            return []
        st = sresp.json().get("status", "ERROR")
        if st == "COMPLETED":
            break
        if st in ("ERROR", "CANCELED"):
            logging.error(f"AQL ended with {st}")
            return []
    else:
        logging.error(f"AQL timed out after {timeout_seconds}s")
        return []

    try:
        rresp = requests.get(f"{qradar_api}/ariel/searches/{sid}/results",
                             headers=headers, verify=False, timeout=120)
        return rresp.json().get("events", [])
    except Exception as e:
        logging.error(f"AQL results error: {e}")
        return []


def severity_num(item: dict):
    """CEF severity -> int (0..10), або None якщо не вдалось визначити."""
    raw = item.get("cef_severity")
    if raw is None:
        return None
    s = str(raw).strip()
    if s.isdigit():
        return int(s)
    return SEV_WORDS.get(s.lower())


def severity_label(sev) -> str:
    if sev is None:
        return "?"
    if sev >= 10:
        return "Critical"
    if sev >= 9:
        return "High"
    if sev >= 6:
        return "Medium"
    if sev >= 3:
        return "Low"
    return "Info"


def recommend_action(item: dict) -> str:
    """Коротка рекомендована дія українською на основі дії агента / важливості."""
    act = (item.get("action") or "").lower()
    sev = item.get("sev_num")
    name = (item.get("alert_name") or "").lower()
    module = (item.get("module") or "").lower()

    blocked = any(x in act for x in ("prevent", "block", "denied"))
    if any(x in name for x in ("ransom", "wildfire", "malware", "trojan")) or "malware" in module:
        if blocked:
            return "✅ Шкідливе ПЗ заблоковано агентом; перевірити джерело, прибрати артефакти з хоста"
        return "🛑 Шкідливе ПЗ лише задетектовано (НЕ заблоковано): ізолювати хост у Cortex, видалити, розслідувати"
    if "behavioral" in name or "bioc" in module or "analytics" in module:
        return "🔍 Поведінкова детекція: перевірити ланцюг процесів у Cortex; якщо легітимно — exception"
    if "credential" in name or "lateral" in name or "exfil" in name:
        return "🚨 Можлива пост-експлуатація: ізолювати хост, перевірити суміжні системи (lateral)"
    if sev is not None and sev >= 9:
        return "🛑 High/Critical: ізолювати хост у Cortex Console, розслідувати"
    if not blocked and act:
        return "⚠️ Лише задетектовано (не заблоковано): перевірити хост і процес у Cortex"
    return "🔍 Перевірити алерт у Cortex Console"


def is_false_positive(item: dict, fp_names: set, fp_ids: set, min_sev: int):
    """Повертає причину FP/відсіву або None якщо алерт треба показати."""
    name = (item.get("alert_name") or "").strip()
    if name in fp_names:
        return f"alert_name_allowlist:{name}"
    eid = (item.get("external_id") or "").strip()
    if eid and eid in fp_ids:
        return "external_id_allowlist"
    sev = item.get("sev_num")
    # sev відома й нижча за поріг -> відсікаємо; невідома -> лишаємо (fail-open).
    if sev is not None and sev < min_sev:
        return f"sev_below_threshold:{sev}<{min_sev}"
    return None


def normalize_event(row: dict) -> dict | None:
    f = parse_cef(row.get("RawPayload") or "")
    if not f:
        return None
    item = {
        "time": row.get("Time"),
        "src": row.get("sourceip"),
        "external_id": f.get("externalId") or "",
        "alert_name": f.get("name"),
        "category": f.get("cat") or f.get("sig_id"),
        "module": f.get("sig_id"),                 # XDR Agent / XDR Analytics / XDR BIOC ...
        "hostname": f.get("shost") or f.get("dvchost") or f.get("dhost"),
        "user": f.get("suser") or row.get("username"),
        "sha256": (f.get("fileHash") or f.get("initiatorSha256") or "").lower(),
        "action": f.get("act"),
        "url": f.get("request"),
        "initiated_by": f.get("cs1"),              # cs1Label="Initiated by"
        "cgo_cmd": f.get("cs5"),                    # cs5Label="CGO CMD"
        "cef_severity": f.get("cef_severity"),
    }
    item["sev_num"] = severity_num(item)
    return item


def dedup_key(item: dict) -> str:
    eid = (item.get("external_id") or "").strip()
    if eid:
        return eid
    # Запасний ключ, якщо externalId відсутній.
    return "|".join([
        item.get("sha256") or "",
        item.get("hostname") or item.get("src") or "?",
        item.get("alert_name") or "?",
    ])


def filter_and_dedupe(events: list, config: dict, dedup_days: int) -> tuple[list, dict]:
    fp_names = set(cfg(config, "cortex_xdr_fp_alert_names"))
    fp_ids = set(str(x) for x in cfg(config, "cortex_xdr_fp_external_ids"))
    min_sev = int(cfg(config, "cortex_xdr_min_severity"))

    stats = {"raw": len(events), "parsed": 0, "fp": 0, "dedup_run": 0, "dedup": 0, "new": 0}
    seen_in_run = set()
    candidates = []
    for row in events:
        item = normalize_event(row)
        if not item:
            continue
        stats["parsed"] += 1
        why = is_false_positive(item, fp_names, fp_ids, min_sev)
        if why:
            stats["fp"] += 1
            continue
        key = dedup_key(item)
        if key in seen_in_run:
            stats["dedup_run"] += 1
            continue
        seen_in_run.add(key)
        item["_key"] = key
        candidates.append(item)

    new_items = []
    with sqlite3.connect(DB_PATH) as conn:
        for it in candidates:
            cur = conn.execute(
                "SELECT 1 FROM cortex_xdr_reported "
                "WHERE external_id=? AND last_reported_ts >= datetime('now', ?)",
                (it["_key"], f"-{int(dedup_days)} days"),
            )
            if cur.fetchone():
                stats["dedup"] += 1
                continue
            new_items.append(it)
            stats["new"] += 1
    return new_items, stats


def mark_reported(items: list) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        for it in items:
            conn.execute(
                """
                INSERT INTO cortex_xdr_reported (external_id, hostname, alert_name)
                VALUES (?, ?, ?)
                ON CONFLICT(external_id) DO UPDATE SET
                    last_reported_ts = CURRENT_TIMESTAMP,
                    report_count = report_count + 1
                """,
                (it["_key"], it.get("hostname") or it.get("src") or "?", it.get("alert_name") or ""),
            )


def fetch_recent_events(qradar_api: str, headers: dict, logsource_filter: str,
                        lookback_hours: int, timeout_s: int, max_rows: int) -> list:
    ls = logsource_filter.replace("'", "''")
    aql = (
        f"SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS Time, "
        f"sourceip, username, UTF8(payload) AS RawPayload "
        f"FROM events "
        f"WHERE LOGSOURCENAME(logsourceid) ILIKE '%{ls}%' "
        f"ORDER BY starttime DESC LIMIT {int(max_rows)} LAST {int(lookback_hours)} HOURS"
    )
    return run_aql(qradar_api, headers, aql, timeout_s)


def build_chat_message(items: list, title: str, max_items: int) -> dict:
    by_host: dict = {}
    for it in items:
        key = (it.get("hostname") or "?", it.get("src") or "?")
        by_host.setdefault(key, []).append(it)

    lines = [f"*{title}*", f"_знайдено {len(items)} алертів на {len(by_host)} хостах_", ""]
    shown = 0
    for (host, src), lst in by_host.items():
        user = next((x.get("user") for x in lst if x.get("user")), None) or "—"
        lines.append(f"*{host}* ({src}) — користувач: `{user}`")
        for it in lst:
            if shown >= max_items:
                break
            name = it.get("alert_name") or "?"
            when = it.get("time") or "?"
            sev = severity_label(it.get("sev_num"))
            act = it.get("action") or "?"
            module = it.get("module") or "?"
            lines.append(f"  • *{name}* ({module}, sev={sev}, дія: {act})")
            lines.append(f"    дата: {when}")
            proc = it.get("initiated_by")
            if proc:
                lines.append(f"    процес: `{proc}`")
            lines.append(f"    рекомендація: {recommend_action(it)}")
            sha = it.get("sha256")
            if sha:
                lines.append(f"    sha256: `{sha}`")
            url = it.get("url")
            if url:
                lines.append(f"    <{url}|відкрити в Cortex Console>")
            shown += 1
        lines.append("")
        if shown >= max_items:
            lines.append(f"_…обрізано до {max_items} записів_")
            break

    return {"text": "\n".join(lines)}


def send_to_chat(webhook_url: str, message: dict) -> bool:
    try:
        resp = requests.post(webhook_url, json=message, timeout=30)
    except Exception as e:
        logging.error(f"Chat webhook POST error: {e}")
        return False
    if resp.status_code in (200, 201, 204):
        return True
    logging.error(f"Chat webhook HTTP {resp.status_code}: {resp.text[:300]}")
    return False


def main() -> None:
    config = load_config()
    qradar_api = f"{config['qradar_url']}/api"
    headers = {"SEC": config["qradar_token"], "Accept": "application/json"}
    run_id = uuid.uuid4().hex[:12]

    # Окремий webhook для Cortex або (fallback) спільний Falcon-простір.
    webhook_url = config.get("cortex_xdr_webhook_url") or config.get("falcon_pua_webhook_url")
    if not webhook_url:
        logging.error("Немає cortex_xdr_webhook_url / falcon_pua_webhook_url у config.json — нічого не шлемо")
        sys.exit(2)

    init_db()

    lock_fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logging.warning("Previous cortex_xdr_scan still running. Skipping this run.")
        sys.exit(0)

    logsource_filter = cfg(config, "cortex_xdr_logsource_filter")
    lookback = cfg(config, "cortex_xdr_lookback_hours")
    dedup_days = cfg(config, "cortex_xdr_dedup_days")
    aql_timeout = cfg(config, "cortex_xdr_aql_timeout_seconds")
    max_rows = cfg(config, "cortex_xdr_max_aql_rows")
    max_report = cfg(config, "cortex_xdr_max_report_items")
    title = cfg(config, "cortex_xdr_report_title")

    logging.info(f"=== Cortex XDR scan run_id={run_id} lookback={lookback}h dedup={dedup_days}d ls~'{logsource_filter}' ===")

    events = fetch_recent_events(qradar_api, headers, logsource_filter, lookback, aql_timeout, max_rows)
    new_items, stats = filter_and_dedupe(events, config, dedup_days)
    logging.info(f"stats: raw={stats['raw']} parsed={stats['parsed']} fp/below={stats['fp']} dedup_run={stats['dedup_run']} dedup_db={stats['dedup']} new={stats['new']}")

    if not new_items:
        logging.info("Нічого нового — звіт не шлемо")
        return

    message = build_chat_message(new_items, title, max_report)
    ok = send_to_chat(webhook_url, message)
    if ok:
        mark_reported(new_items)
        logging.info(f"Звіт надіслано ({len(new_items)} items), state оновлено")
    else:
        logging.error("Webhook fail — state НЕ оновлено, спробуємо завтра")


if __name__ == "__main__":
    main()
