"""botnet_scan.py — періодичний catch-up + cleanup для ME-PA-Suspicious-IP-Addresses.

Запускається окремим процесом (cron / systemd timer). За один запуск виконує дві фази:

1) REVIEW — обходимо поточні entries в ME-PA-Suspicious-IP-Addresses.
   Якщо `now - entry.last_seen > review_stale_hours` (за замовч. 48г) — DELETE.
   Радарські правила оновлюють last_seen при кожному ре-тригері; "стара" відмітка
   означає що з цього IP давно нічого не приходило → блок зробив свою справу,
   звільняємо лист. (Радар сам ескалує таймаути блокування — middleware їх не
   дублює.)

2) HUNT — AQL за останні N днів (за замовч. 7) групує auth-події по sourceip
   і ловить slow-rotation ботнетів, які НЕ дотягують до жодного per-IP порогу
   правил (Failed≥5∧Failed≤30∧Succeeded=0∧Unique_Users≥2). Кандидатів додає
   у ME-PA-Suspicious-IP-Addresses без TTL — далі вже працюють існуючі радарські
   правила (Block bruteforce logins by syspicious list → push to PA).

Виключаємо: IP вже в suspicious-наборі, IP у внутрішніх asset-refsets
(Web/SSH/Mail/Windows/...), приватні діапазони (RFC1918).

State: окрема таблиця botnet_scan у тій самій ai_state.db.
Dry-run: config.botnet_dry_run=true → реальні ADD/DELETE не робляться, лиш логуються.
"""
import json
import os
import sys
import time
import sqlite3
import logging
import urllib3
import ipaddress
import fcntl
import urllib.parse
import uuid
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "ai_state.db")
LOCK_FILE = os.path.join(BASE_DIR, "botnet_scan.lock")
LOG_FILE = os.path.join(BASE_DIR, "botnet_scan.log")

SUSPICIOUS_SET_NAME = "ME-PA-Suspicious-IP-Addresses"

# QID-и невдалої аутентифікації — з 5 правил-наповнювачів refset
FAILED_QIDS = (5000475, 44250069, 44250168, 44250910, 53531473)
# QID-и успішної аутентифікації які мають свій ID
SUCCESS_QIDS = (4624, 53531474)
# Для SSH окремого QID немає — успіх ловимо по low-level category name
# (поєднання з dst у SSH Servers refset не потрібне для нашої цілі: будь-який success
# з цього sourceip — позитивний сигнал, навіть якщо це не SSH)
SUCCESS_CATEGORY_NAMES = ("Admin Login Successful", "Host Login Succeeded")

DEFAULTS = {
    "botnet_scan_lookback_days": 7,
    "botnet_scan_max_adds_per_run": 100,
    "botnet_scan_review_stale_hours": 48,
    "botnet_scan_min_failed": 5,
    "botnet_scan_max_failed": 30,
    "botnet_scan_min_unique_users": 2,
    "botnet_scan_min_time_span_seconds": 3600,
    "botnet_scan_aql_timeout_seconds": 600,
    "botnet_scan_internal_refsets": [
        "Web Servers",
        "SSH Servers",
        "Mail Servers",
        "Windows Servers",
        "LDAP Servers",
        "DHCP Servers",
        "DNS Servers",
        "Database Servers",
    ],
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
            CREATE TABLE IF NOT EXISTS botnet_scan (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                scan_run_id TEXT NOT NULL,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_botnet_scan_ip ON botnet_scan(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_botnet_scan_run ON botnet_scan(scan_run_id)")


def is_local_or_invalid(ip_str: str) -> bool:
    """RFC1918 + multicast + loopback + reserved. Малформовані рядки теж відсікаємо."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        return True


def get_refset_data(qradar_api: str, headers: dict, name: str) -> list:
    url = f"{qradar_api}/reference_data/sets/{urllib.parse.quote(name)}?fields=data"
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=30)
        if resp.status_code != 200:
            logging.warning(f"GET refset '{name}' failed: HTTP {resp.status_code}")
            return []
        return resp.json().get("data", [])
    except Exception as e:
        logging.warning(f"GET refset '{name}' error: {e}")
        return []


def build_internal_ip_set(qradar_api: str, headers: dict, refset_names: list) -> set:
    internal: set = set()
    for name in refset_names:
        for item in get_refset_data(qradar_api, headers, name):
            v = item.get("value")
            if v:
                internal.add(v)
    return internal


def remove_ip_from_set(qradar_api, headers, set_name, ip, dry_run) -> tuple[bool, str]:
    if dry_run:
        return True, "dry_run"
    url = f"{qradar_api}/reference_data/sets/{urllib.parse.quote(set_name)}/{urllib.parse.quote(ip)}"
    try:
        resp = requests.delete(url, headers=headers, verify=False, timeout=15)
    except Exception as e:
        return False, f"exception: {e}"
    if resp.status_code in (200, 204):
        return True, "removed"
    if resp.status_code == 404:
        return True, "not_present"
    return False, f"http_{resp.status_code}: {resp.text[:200]}"


def add_ip_to_set(qradar_api, headers, set_name, ip, dry_run) -> tuple[bool, str]:
    if dry_run:
        return True, "dry_run"
    url = f"{qradar_api}/reference_data/sets/{urllib.parse.quote(set_name)}?value={urllib.parse.quote(ip)}"
    try:
        resp = requests.post(url, headers=headers, verify=False, timeout=15)
    except Exception as e:
        return False, f"exception: {e}"
    if resp.status_code in (200, 201):
        return True, "added"
    if resp.status_code == 409:
        return True, "already_exists"
    return False, f"http_{resp.status_code}: {resp.text[:200]}"


def run_aql(qradar_api: str, headers: dict, aql: str, timeout_seconds: int) -> list:
    """POST /ariel/searches → poll → fetch results."""
    try:
        resp = requests.post(
            f"{qradar_api}/ariel/searches?query_expression={urllib.parse.quote(aql)}",
            headers=headers, verify=False, timeout=30,
        )
    except Exception as e:
        logging.error(f"AQL submit error: {e}")
        return []
    if resp.status_code not in (200, 201):
        logging.error(f"AQL submit HTTP {resp.status_code}: {resp.text[:300]}")
        return []
    search_id = resp.json().get("search_id")
    if not search_id:
        logging.error("AQL: empty search_id")
        return []

    waited = 0
    while waited < timeout_seconds:
        time.sleep(3)
        waited += 3
        try:
            sresp = requests.get(
                f"{qradar_api}/ariel/searches/{search_id}",
                headers=headers, verify=False, timeout=15,
            )
        except Exception as e:
            logging.error(f"AQL status error: {e}")
            return []
        if sresp.status_code != 200:
            logging.error(f"AQL status HTTP {sresp.status_code}")
            return []
        status = sresp.json().get("status", "ERROR")
        if status == "COMPLETED":
            break
        if status == "ERROR":
            logging.error("AQL search ended with ERROR")
            return []
    else:
        logging.error(f"AQL timed out after {timeout_seconds}s")
        return []

    try:
        rresp = requests.get(
            f"{qradar_api}/ariel/searches/{search_id}/results",
            headers=headers, verify=False, timeout=120,
        )
        return rresp.json().get("events", [])
    except Exception as e:
        logging.error(f"AQL results fetch error: {e}")
        return []


def review_existing_entries(qradar_api, headers, config, run_id) -> int:
    """Прохід по поточних entries в ME-PA-Suspicious-IP-Addresses.
    Якщо last_seen старше за поріг — видалити (IP вгомонився, блок зробив справу)."""
    threshold_hours = cfg(config, "botnet_scan_review_stale_hours")
    dry_run = config.get("botnet_dry_run", False)
    threshold_ms = threshold_hours * 3600 * 1000
    now_ms = int(time.time() * 1000)

    entries = get_refset_data(qradar_api, headers, SUSPICIOUS_SET_NAME)
    logging.info(f"REVIEW: {len(entries)} entries currently in {SUSPICIOUS_SET_NAME}")

    removed = 0
    with sqlite3.connect(DB_PATH) as conn:
        for entry in entries:
            ip = entry.get("value")
            last_seen = entry.get("last_seen")
            if not ip or last_seen is None:
                continue
            age_h = (now_ms - int(last_seen)) // 3600000
            if (now_ms - int(last_seen)) < threshold_ms:
                conn.execute(
                    "INSERT INTO botnet_scan (ip, action, reason, scan_run_id) VALUES (?, ?, ?, ?)",
                    (ip, "keep", f"age={age_h}h<{threshold_hours}h", run_id),
                )
                continue
            ok, msg = remove_ip_from_set(qradar_api, headers, SUSPICIOUS_SET_NAME, ip, dry_run)
            action = "remove_dry" if dry_run else ("remove" if ok else "remove_failed")
            conn.execute(
                "INSERT INTO botnet_scan (ip, action, reason, scan_run_id) VALUES (?, ?, ?, ?)",
                (ip, action, f"age={age_h}h, {msg}", run_id),
            )
            if ok:
                removed += 1
                logging.info(f"  [{'DRY' if dry_run else 'OK'}] removed {ip} (age {age_h}h)")
            else:
                logging.error(f"  [FAIL] remove {ip}: {msg}")
    logging.info(f"REVIEW: {removed} entries removed (dry_run={dry_run})")
    return removed


def hunt_new_candidates(qradar_api, headers, config, run_id) -> int:
    """AQL по auth-подіях за last N днів. Сігнатура: success=0, моде failed, ≥2 unique users."""
    lookback = cfg(config, "botnet_scan_lookback_days")
    min_failed = cfg(config, "botnet_scan_min_failed")
    max_failed = cfg(config, "botnet_scan_max_failed")
    min_users = cfg(config, "botnet_scan_min_unique_users")
    min_span_s = cfg(config, "botnet_scan_min_time_span_seconds")
    max_adds = cfg(config, "botnet_scan_max_adds_per_run")
    internal_refsets = cfg(config, "botnet_scan_internal_refsets")
    aql_timeout = cfg(config, "botnet_scan_aql_timeout_seconds")
    dry_run = config.get("botnet_dry_run", False)

    failed_csv = ",".join(str(q) for q in FAILED_QIDS)
    success_csv = ",".join(str(q) for q in SUCCESS_QIDS)
    cats_csv = ",".join(f"'{c}'" for c in SUCCESS_CATEGORY_NAMES)

    failed_expr = f"SUM(CASE WHEN qid IN ({failed_csv}) THEN 1 ELSE 0 END)"
    success_expr = f"SUM(CASE WHEN qid IN ({success_csv}) OR CATEGORYNAME(category) IN ({cats_csv}) THEN 1 ELSE 0 END)"
    users_expr = "UNIQUECOUNT(username)"

    aql = (
        f"SELECT sourceip AS Source_IP, "
        f"{failed_expr} AS Failed, "
        f"{success_expr} AS Succeeded, "
        f"{users_expr} AS Unique_Users, "
        f"MIN(starttime) AS First_Seen_Ms, "
        f"MAX(starttime) AS Last_Seen_Ms "
        f"FROM events "
        f"WHERE qid IN ({failed_csv},{success_csv}) "
        f"OR CATEGORYNAME(category) IN ({cats_csv}) "
        f"GROUP BY sourceip "
        f"HAVING {failed_expr} >= {min_failed} "
        f"AND {failed_expr} <= {max_failed} "
        f"AND {success_expr} = 0 "
        f"AND {users_expr} >= {min_users} "
        f"ORDER BY Failed DESC "
        f"LIMIT 10000 LAST {lookback} DAYS"
    )

    logging.info(
        f"HUNT: lookback={lookback}d, failed={min_failed}-{max_failed}, "
        f"min_users={min_users}, min_span={min_span_s}s, cap={max_adds}"
    )
    candidates = run_aql(qradar_api, headers, aql, aql_timeout)
    logging.info(f"HUNT: AQL returned {len(candidates)} raw candidates")

    suspicious_now = {e.get("value") for e in get_refset_data(qradar_api, headers, SUSPICIOUS_SET_NAME) if e.get("value")}
    internal_ips = build_internal_ip_set(qradar_api, headers, internal_refsets)
    logging.info(f"HUNT: {len(suspicious_now)} already suspicious, {len(internal_ips)} internal asset IPs")

    added = 0
    with sqlite3.connect(DB_PATH) as conn:
        for cand in candidates:
            if added >= max_adds:
                logging.info(f"HUNT: cap {max_adds} reached, останні кандидати пропущені")
                break
            ip = cand.get("Source_IP")
            failed = int(cand.get("Failed", 0) or 0)
            succeeded = int(cand.get("Succeeded", 0) or 0)
            users = int(cand.get("Unique_Users", 0) or 0)
            first_ms = int(cand.get("First_Seen_Ms", 0) or 0)
            last_ms = int(cand.get("Last_Seen_Ms", 0) or 0)
            span_s = (last_ms - first_ms) // 1000 if last_ms and first_ms else 0

            def _skip(why: str):
                conn.execute(
                    "INSERT INTO botnet_scan (ip, action, reason, scan_run_id) VALUES (?, ?, ?, ?)",
                    (ip or "?", "skip", why, run_id),
                )

            if not ip:
                continue
            if succeeded > 0:
                _skip(f"defensive_succeeded={succeeded}")
                continue
            if span_s < min_span_s:
                _skip(f"short_span={span_s}s")
                continue
            if ip in suspicious_now:
                _skip("already_in_suspicious")
                continue
            if ip in internal_ips:
                _skip("internal_asset")
                continue
            if is_local_or_invalid(ip):
                _skip("rfc1918_or_local")
                continue

            ok, msg = add_ip_to_set(qradar_api, headers, SUSPICIOUS_SET_NAME, ip, dry_run)
            action = "add_dry" if dry_run else ("add" if ok else "add_failed")
            conn.execute(
                "INSERT INTO botnet_scan (ip, action, reason, scan_run_id) VALUES (?, ?, ?, ?)",
                (ip, action, f"failed={failed}, users={users}, span={span_s}s, {msg}", run_id),
            )
            if ok:
                added += 1
                logging.info(f"  [{'DRY' if dry_run else 'OK'}] added {ip} (failed={failed}, users={users}, span={span_s}s)")
            else:
                logging.error(f"  [FAIL] add {ip}: {msg}")
    logging.info(f"HUNT: {added} entries added (dry_run={dry_run})")
    return added


def main() -> None:
    config = load_config()
    qradar_api = f"{config['qradar_url']}/api"
    headers = {"SEC": config["qradar_token"], "Accept": "application/json"}
    run_id = uuid.uuid4().hex[:12]

    init_db()

    lock_fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logging.warning("Previous botnet_scan still running. Skipping this run.")
        sys.exit(0)

    dry = config.get("botnet_dry_run", False)
    logging.info(f"=== Botnet scan run_id={run_id} dry_run={dry} ===")
    try:
        review_existing_entries(qradar_api, headers, config, run_id)
        hunt_new_candidates(qradar_api, headers, config, run_id)
    except Exception as e:
        logging.exception(f"Botnet scan failed: {e}")
        sys.exit(2)
    logging.info(f"=== Botnet scan done run_id={run_id} ===")


if __name__ == "__main__":
    main()
