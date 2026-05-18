"""falcon_pua_scan.py — щоденний звіт по CrowdStrike Falcon PUP / ML-детекціях.

Стягує події за останні N годин по двох QID-ах:
  103750325 — Machine Learning : Endpoint Protection Platform (EPP) Detection Summary Event
  103750326 — Malware            : Endpoint Protection Platform (EPP) Detection Summary Event

Парсить LEEF payload Falcon-а, виключає відомі FP-патерни (Windows OS update
компоненти, 1C-бінарі, dev-toolchains, польські податкові .f3i файли тощо),
дедуплікує по (sha256, hostname) проти таблиці falcon_pua_reported в ai_state.db
і, якщо щось залишилося, шле звіт у Google Chat через webhook.

Запускається через cron (раз на добу зранку). Lock через fcntl на falcon_pua_scan.lock.
Конфіг — секції з префіксом `falcon_pua_*` у /opt/qradar-middleware/config.json.

State: окрема таблиця falcon_pua_reported в тій самій ai_state.db.
Webhook URL — тільки в config.json (gitignored), НЕ комітити в репо.
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
import urllib.parse
import uuid
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "ai_state.db")
LOCK_FILE = os.path.join(BASE_DIR, "falcon_pua_scan.lock")
LOG_FILE = os.path.join(BASE_DIR, "falcon_pua_scan.log")

ML_QID = 103750325   # Sensor-based ML high-confidence
EPP_QID = 103750326  # PUP / standard malware detection

DEFAULTS = {
    "falcon_pua_lookback_hours": 25,
    "falcon_pua_dedup_days": 30,
    "falcon_pua_aql_timeout_seconds": 300,
    "falcon_pua_max_aql_rows": 5000,
    "falcon_pua_max_report_items": 50,
    # Поріг важливості Falcon-події. Беремо тільки sev > цього значення.
    # Falcon-шкала: 10=Info, 20=Low, 30=Medium, 40=High, 50=Critical.
    # Default 40 → пропускаємо лише High+ і Critical, відсікаємо ML/PUP шум.
    "falcon_pua_min_severity": 40,
    # Регекси шляхів, що завжди FP (Falcon ML / EPP помилково тригерить).
    # Регістронечутливо, match по filePath. Подвійні слеши Falcon-style.
    "falcon_pua_fp_path_regex": [
        r"\\Windows\\WinSxS\\",
        r"\\Windows\\SoftwareDistribution\\Download\\",
        r"\\AppData\\Local\\1C\\1cv8\\",
        r"\\AppData\\Local\\Arduino15\\packages\\",
        r"\\Visual Paradigm Project Viewer",
        r"\\Documents\\IPSPI\\F3I\\",
        r"\\AppData\\Local\\Programs\\ShareX\\unins\d+\.exe",
    ],
    # Імена файлів, що завжди FP (regardless of path)
    "falcon_pua_fp_filenames": [
        "VisualAssistExe.exe",
        "RegsvrPower.exe",
        "Template.bin",
        "perfnet.dll",
    ],
    # SHA256 (full hex) — індивідуальні allowlist-хеші, що вже триаджено як FP
    "falcon_pua_fp_sha256": [],
    # Префікс заголовка повідомлення у Google Chat
    "falcon_pua_report_title": "🛡️ Falcon EPP/ML — щоденний звіт",
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
            CREATE TABLE IF NOT EXISTS falcon_pua_reported (
                sha256 TEXT NOT NULL,
                hostname TEXT NOT NULL,
                filename TEXT,
                first_reported_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_reported_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                report_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (sha256, hostname)
            )
            """
        )


def parse_leef(payload: str) -> dict:
    """LEEF:1.0|Vendor|Product|Version|EventName|key=value\\tkey=value..."""
    if not payload:
        return {}
    parts = payload.split("|", 5)
    if len(parts) < 6:
        return {}
    body = parts[5]
    out = {}
    for kv in body.split("\t"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k.strip()] = v.strip()
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


def is_false_positive(item: dict, fp_path_re: list, fp_filenames: set, fp_sha256: set, min_sev: int) -> str | None:
    """Повертає причину FP або None якщо подія підозріла."""
    try:
        sev = int(item.get("sev") or 0)
    except (TypeError, ValueError):
        sev = 0
    if sev <= min_sev:
        return f"sev_below_threshold:{sev}<={min_sev}"
    sha = (item.get("sha256") or "").lower()
    if sha and sha in fp_sha256:
        return f"sha256_allowlist"
    fname = (item.get("filename") or "").strip()
    if fname in fp_filenames:
        return f"filename_allowlist:{fname}"
    fpath = item.get("filepath") or ""
    for rx in fp_path_re:
        if rx.search(fpath):
            return f"path_regex:{rx.pattern}"
    return None


def fetch_recent_events(qradar_api: str, headers: dict, lookback_hours: int,
                        timeout_s: int, max_rows: int) -> list:
    aql = (
        f"SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS Time, "
        f"sourceip, username, UTF8(payload) AS RawPayload "
        f"FROM events "
        f"WHERE qid IN ({ML_QID},{EPP_QID}) "
        f"ORDER BY starttime DESC LIMIT {int(max_rows)} LAST {int(lookback_hours)} HOURS"
    )
    return run_aql(qradar_api, headers, aql, timeout_s)


def normalize_event(row: dict) -> dict | None:
    f = parse_leef(row.get("RawPayload") or "")
    if not f:
        return None
    # Falcon LEEF puts double-backslashes as path separators — normalize to single
    filepath = (f.get("filePath") or "").replace("\\\\", "\\")
    return {
        "time": row.get("Time"),
        "src": row.get("sourceip"),
        "user_short": row.get("username"),       # QRadar normalized username (often empty for Falcon)
        "hostname": f.get("resource"),           # CrowdStrike: ME142, BRK24, ...
        "filename": f.get("fileName"),
        "filepath": filepath,
        "sha256": (f.get("sha256") or "").lower(),
        "tactic": f.get("tactic"),
        "technique": f.get("technique"),
        "sev": f.get("sev"),
        "qid_name": "EPP/PUP" if f.get("technique") in ("PUP", "Adware/PUP") else "ML",
        "url": (f.get("url") or "").replace("\\=", "="),
    }


def filter_and_dedupe(events: list, config: dict, dedup_days: int) -> tuple[list, dict]:
    fp_path_re = [re.compile(rx, re.IGNORECASE) for rx in cfg(config, "falcon_pua_fp_path_regex")]
    fp_filenames = set(cfg(config, "falcon_pua_fp_filenames"))
    fp_sha256 = set(s.lower() for s in cfg(config, "falcon_pua_fp_sha256"))
    min_sev = int(cfg(config, "falcon_pua_min_severity"))

    stats = {"raw": len(events), "parsed": 0, "fp": 0, "dedup_run": 0, "dedup": 0, "new": 0}
    # Deduplicate WITHIN this run by (sha256, hostname, filepath) — Falcon emits a
    # separate event for each scan/access of the same file, we only need one row.
    seen_in_run = set()
    candidates = []
    for row in events:
        item = normalize_event(row)
        if not item:
            continue
        stats["parsed"] += 1
        why = is_false_positive(item, fp_path_re, fp_filenames, fp_sha256, min_sev)
        if why:
            item["fp_reason"] = why
            stats["fp"] += 1
            continue
        key = (item.get("sha256"), item.get("hostname") or item.get("src") or "?", item.get("filepath") or "")
        if key in seen_in_run:
            stats["dedup_run"] += 1
            continue
        seen_in_run.add(key)
        candidates.append(item)

    # Deduplicate by (sha256, hostname) using state DB
    new_items = []
    with sqlite3.connect(DB_PATH) as conn:
        for it in candidates:
            sha = it["sha256"]
            host = it["hostname"] or it.get("src") or "?"
            if not sha:
                new_items.append(it)
                stats["new"] += 1
                continue
            cur = conn.execute(
                "SELECT 1 FROM falcon_pua_reported "
                "WHERE sha256=? AND hostname=? "
                "AND last_reported_ts >= datetime('now', ?)",
                (sha, host, f"-{int(dedup_days)} days"),
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
            sha = it["sha256"]
            host = it["hostname"] or it.get("src") or "?"
            fname = it.get("filename") or ""
            if not sha:
                continue
            conn.execute(
                """
                INSERT INTO falcon_pua_reported (sha256, hostname, filename)
                VALUES (?, ?, ?)
                ON CONFLICT(sha256, hostname) DO UPDATE SET
                    last_reported_ts = CURRENT_TIMESTAMP,
                    report_count = report_count + 1
                """,
                (sha, host, fname),
            )


def build_chat_message(items: list, title: str, max_items: int) -> dict:
    # Групуємо по hostname для компактного звіту
    by_host: dict = {}
    for it in items:
        key = (it.get("hostname") or "?", it.get("src") or "?")
        by_host.setdefault(key, []).append(it)

    lines = [f"*{title}*", f"_знайдено {len(items)} підозрілих об'єктів на {len(by_host)} хостах_", ""]
    shown = 0
    for (host, src), lst in by_host.items():
        # Зберемо першого юзера що не порожній (Falcon інколи не дає юзера на сам файл)
        user = next((x.get("user_short") for x in lst if x.get("user_short")), None) or "—"
        lines.append(f"*{host}* ({src}) — користувач: `{user}`")
        for it in lst:
            if shown >= max_items:
                break
            fname = it.get("filename") or "?"
            when = it.get("time") or "?"
            sha = it.get("sha256") or ""
            tac = it.get("tactic") or "?"
            tech = it.get("technique") or "?"
            sev = it.get("sev") or "?"
            lines.append(f"  • `{fname}` ({tac}/{tech}, sev={sev})")
            lines.append(f"    дата: {when}")
            if sha:
                lines.append(f"    sha256: `{sha}`")
            falcon_url = it.get("url")
            if falcon_url:
                lines.append(f"    <{falcon_url}|відкрити в Falcon Console>")
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

    webhook_url = config.get("falcon_pua_webhook_url")
    if not webhook_url:
        logging.error("falcon_pua_webhook_url не заданий у config.json — нічого не шлемо")
        sys.exit(2)

    init_db()

    lock_fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logging.warning("Previous falcon_pua_scan still running. Skipping this run.")
        sys.exit(0)

    lookback = cfg(config, "falcon_pua_lookback_hours")
    dedup_days = cfg(config, "falcon_pua_dedup_days")
    aql_timeout = cfg(config, "falcon_pua_aql_timeout_seconds")
    max_rows = cfg(config, "falcon_pua_max_aql_rows")
    max_report = cfg(config, "falcon_pua_max_report_items")
    title = cfg(config, "falcon_pua_report_title")

    logging.info(f"=== Falcon PUA scan run_id={run_id} lookback={lookback}h dedup={dedup_days}d ===")

    events = fetch_recent_events(qradar_api, headers, lookback, aql_timeout, max_rows)
    new_items, stats = filter_and_dedupe(events, config, dedup_days)
    logging.info(f"stats: raw={stats['raw']} parsed={stats['parsed']} fp={stats['fp']} dedup_run={stats['dedup_run']} dedup_db={stats['dedup']} new={stats['new']}")

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
