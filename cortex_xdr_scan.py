"""cortex_xdr_scan.py — щоденний звіт по алертах Palo Alto Cortex XDR.

Джерело — напряму Cortex XDR Public API (`/public_api/v1/alerts/get_alerts_multi_events`),
НЕ QRadar: syslog-фід Cortex → api-gw → QRadar уже двічі мовчки вмирав (з 2026-08-04 і
далі — 0 подій), тож сканер, що читав QRadar, нічого не бачив. API-ключ — read-only
(роль лише на перегляд алертів), рівень Advanced (підпис nonce+timestamp, ключ у запиті
не передається).

Далі як і раніше: виключаємо Informational / тестові / allowlist / whitelisted-алерти,
дедуплікуємо по alert_id проти таблиці cortex_xdr_reported в ai_state.db і, якщо щось
залишилося, шлемо звіт у Google Chat через webhook.

Запускається через systemd timer (раз на добу). Lock через fcntl на cortex_xdr_scan.lock.
Конфіг — ключі з префіксом `cortex_xdr_*` у /opt/qradar-middleware/config.json.
Webhook: окремий cortex_xdr_webhook_url або (fallback) спільний falcon_pua_webhook_url.

Секрети (cortex_xdr_api_key, webhook URL) — тільки в config.json (gitignored), НЕ комітити.
"""
import hashlib
import json
import os
import secrets
import string
import sys
import time
import sqlite3
import logging
import fcntl
import uuid
import requests

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "ai_state.db")
LOCK_FILE = os.path.join(BASE_DIR, "cortex_xdr_scan.lock")
LOG_FILE = os.path.join(BASE_DIR, "cortex_xdr_scan.log")

# Severity з API (слово) -> число за шкалою CEF: Info=0, Low=3, Med=6, High=9, Crit=10.
SEV_WORDS = {
    "informational": 0, "info": 0, "low": 3, "medium": 6, "med": 6,
    "high": 9, "critical": 10, "crit": 10,
}

DEFAULTS = {
    "cortex_xdr_lookback_hours": 25,
    "cortex_xdr_dedup_days": 30,
    "cortex_xdr_max_report_items": 50,
    # API: FQDN тенанта (з префіксом api- або без), ID і сам ключ. Ключ — лише в config.json.
    "cortex_xdr_api_fqdn": "",
    "cortex_xdr_api_key_id": "",
    "cortex_xdr_api_key": "",
    # "advanced" (підпис nonce+timestamp) або "standard" (ключ як є в Authorization).
    "cortex_xdr_api_security": "advanced",
    # База для посилань на алерт у консолі; порожньо = https://<fqdn без api->.
    "cortex_xdr_console_url": "",
    "cortex_xdr_page_size": 100,
    "cortex_xdr_max_alerts": 1000,
    "cortex_xdr_api_timeout_seconds": 60,
    # Поріг важливості. Беремо тільки sev >= цього значення.
    # Шкала: 0=Info, 3=Low, 6=Medium, 9=High, 10=Critical.
    # Default 3 → відсікаємо лише Informational, лишаємо Low і вище.
    "cortex_xdr_min_severity": 3,
    # Алерти, позначені в консолі як whitelisted (exception), не показуємо.
    "cortex_xdr_skip_whitelisted": True,
    # Назви алертів, що завжди ігноруємо (тестові / відомі FP).
    "cortex_xdr_fp_alert_names": [
        "Example Cortex XDR Alert",
    ],
    # Окремі alert_id, що вже триаджено як FP.
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


def api_host(config: dict) -> str:
    fqdn = str(cfg(config, "cortex_xdr_api_fqdn")).strip().removeprefix("https://").strip("/")
    return fqdn if fqdn.startswith("api-") else f"api-{fqdn}"


def console_base(config: dict) -> str:
    url = str(cfg(config, "cortex_xdr_console_url")).strip().rstrip("/")
    if url:
        return url
    return "https://" + api_host(config).removeprefix("api-")


def api_headers(config: dict) -> dict:
    key_id = str(cfg(config, "cortex_xdr_api_key_id"))
    key = str(cfg(config, "cortex_xdr_api_key"))
    if str(cfg(config, "cortex_xdr_api_security")).lower() == "standard":
        auth = key
        extra = {}
    else:
        # Advanced: sha256(key + nonce + timestamp_ms); nonce — 64 випадкові символи.
        nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        ts = str(int(time.time() * 1000))
        auth = hashlib.sha256(f"{key}{nonce}{ts}".encode()).hexdigest()
        extra = {"x-xdr-timestamp": ts, "x-xdr-nonce": nonce}
    return {"x-xdr-auth-id": key_id, "Authorization": auth,
            "Content-Type": "application/json", **extra}


def fetch_recent_alerts(config: dict, lookback_hours: int) -> list | None:
    """Усі алерти з creation_time за останні lookback_hours. None — помилка API."""
    url = f"https://{api_host(config)}/public_api/v1/alerts/get_alerts_multi_events"
    since = int((time.time() - lookback_hours * 3600) * 1000)
    page = int(cfg(config, "cortex_xdr_page_size"))
    cap = int(cfg(config, "cortex_xdr_max_alerts"))
    timeout = int(cfg(config, "cortex_xdr_api_timeout_seconds"))
    out = []
    while len(out) < cap:
        body = {"request_data": {
            "filters": [{"field": "creation_time", "operator": "gte", "value": since}],
            "search_from": len(out),
            "search_to": len(out) + page,
            "sort": {"field": "creation_time", "keyword": "asc"},
        }}
        try:
            # Заголовки щоразу нові: nonce/timestamp у Advanced одноразові.
            resp = requests.post(url, headers=api_headers(config), json=body, timeout=timeout)
        except Exception as e:
            logging.error(f"Cortex API error: {e}")
            return None
        if resp.status_code != 200:
            # Тіло відповіді не містить ключа, але обрізаємо про всяк випадок.
            logging.error(f"Cortex API HTTP {resp.status_code}: {resp.text[:300]}")
            return None
        reply = resp.json().get("reply", {})
        batch = reply.get("alerts") or []
        out.extend(batch)
        if len(batch) < page or len(out) >= int(reply.get("total_count") or 0):
            break
    return out[:cap]


def severity_num(item: dict):
    """Severity -> int (0..10), або None якщо не вдалось визначити."""
    raw = item.get("severity_raw")
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


def is_false_positive(item: dict, fp_names: set, fp_ids: set, min_sev: int, skip_whitelisted: bool):
    """Повертає причину FP/відсіву або None якщо алерт треба показати."""
    name = (item.get("alert_name") or "").strip()
    if name in fp_names:
        return f"alert_name_allowlist:{name}"
    eid = (item.get("external_id") or "").strip()
    if eid and eid in fp_ids:
        return "external_id_allowlist"
    if skip_whitelisted and item.get("whitelisted"):
        return "whitelisted"
    sev = item.get("sev_num")
    # sev відома й нижча за поріг -> відсікаємо; невідома -> лишаємо (fail-open).
    if sev is not None and sev < min_sev:
        return f"sev_below_threshold:{sev}<{min_sev}"
    return None


def _host_ip(ips) -> str:
    """З кількох адрес агента беремо корпоративну (172.*), інакше першу."""
    if isinstance(ips, str):
        ips = [ips]
    ips = [i for i in (ips or []) if i]
    return next((i for i in ips if i.startswith("172.")), ips[0] if ips else "")


def normalize_alert(alert: dict, console: str) -> dict:
    ev = (alert.get("events") or [{}])[0] or {}
    ts = alert.get("detection_timestamp") or alert.get("creation_time")
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts) / 1000)) if ts else None
    alert_id = str(alert.get("alert_id") or "")
    module = " / ".join(x for x in (alert.get("source"), ev.get("module_id")) if x)
    item = {
        "time": when,
        "src": _host_ip(alert.get("host_ip")),
        "external_id": alert_id,
        "alert_name": alert.get("name"),
        "category": alert.get("category"),
        "module": module,                           # XDR Agent / Local Analysis, XDR BIOC ...
        "hostname": alert.get("host_name"),
        "user": ev.get("user_name") or ev.get("actor_effective_username"),
        "sha256": (ev.get("action_file_sha256") or ev.get("actor_process_image_sha256")
                   or ev.get("causality_actor_process_image_sha256") or "").lower(),
        "action": alert.get("action_pretty") or alert.get("action"),
        "url": f"{console}/alerts/{alert_id}" if alert_id else None,
        "initiated_by": ev.get("actor_process_image_path") or ev.get("causality_actor_process_image_path"),
        "description": alert.get("description"),
        "whitelisted": bool(alert.get("is_whitelisted")),
        "severity_raw": alert.get("severity"),
    }
    item["sev_num"] = severity_num(item)
    return item


def dedup_key(item: dict) -> str:
    eid = (item.get("external_id") or "").strip()
    if eid:
        return eid
    # Запасний ключ, якщо alert_id відсутній.
    return "|".join([
        item.get("sha256") or "",
        item.get("hostname") or item.get("src") or "?",
        item.get("alert_name") or "?",
    ])


def filter_and_dedupe(alerts: list, config: dict, dedup_days: int) -> tuple[list, dict]:
    fp_names = set(cfg(config, "cortex_xdr_fp_alert_names"))
    fp_ids = set(str(x) for x in cfg(config, "cortex_xdr_fp_external_ids"))
    min_sev = int(cfg(config, "cortex_xdr_min_severity"))
    skip_wl = bool(cfg(config, "cortex_xdr_skip_whitelisted"))
    console = console_base(config)

    stats = {"raw": len(alerts), "fp": 0, "dedup_run": 0, "dedup": 0, "new": 0}
    seen_in_run = set()
    candidates = []
    for alert in alerts:
        item = normalize_alert(alert, console)
        why = is_false_positive(item, fp_names, fp_ids, min_sev, skip_wl)
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
                lines.append(f"    файл/процес: `{proc}`")
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
    run_id = uuid.uuid4().hex[:12]
    dry_run = "--dry-run" in sys.argv

    # Окремий webhook для Cortex або (fallback) спільний Falcon-простір.
    webhook_url = config.get("cortex_xdr_webhook_url") or config.get("falcon_pua_webhook_url")
    if not webhook_url and not dry_run:
        logging.error("Немає cortex_xdr_webhook_url / falcon_pua_webhook_url у config.json — нічого не шлемо")
        sys.exit(2)
    if not (cfg(config, "cortex_xdr_api_fqdn") and cfg(config, "cortex_xdr_api_key_id") and cfg(config, "cortex_xdr_api_key")):
        logging.error("Немає cortex_xdr_api_fqdn / cortex_xdr_api_key_id / cortex_xdr_api_key у config.json")
        sys.exit(2)

    init_db()

    lock_fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logging.warning("Previous cortex_xdr_scan still running. Skipping this run.")
        sys.exit(0)

    lookback = cfg(config, "cortex_xdr_lookback_hours")
    dedup_days = cfg(config, "cortex_xdr_dedup_days")
    max_report = cfg(config, "cortex_xdr_max_report_items")
    title = cfg(config, "cortex_xdr_report_title")

    logging.info(f"=== Cortex XDR scan run_id={run_id} lookback={lookback}h dedup={dedup_days}d "
                 f"api={api_host(config)}{' DRY-RUN' if dry_run else ''} ===")

    alerts = fetch_recent_alerts(config, int(lookback))
    if alerts is None:
        logging.error("Cortex API недоступний — звіт не формуємо, спробуємо наступного запуску")
        sys.exit(1)
    new_items, stats = filter_and_dedupe(alerts, config, dedup_days)
    logging.info(f"stats: raw={stats['raw']} fp/below={stats['fp']} dedup_run={stats['dedup_run']} "
                 f"dedup_db={stats['dedup']} new={stats['new']}")

    if not new_items:
        logging.info("Нічого нового — звіт не шлемо")
        return

    message = build_chat_message(new_items, title, max_report)
    if dry_run:
        print(message["text"])
        logging.info("DRY-RUN: звіт не надіслано, state не оновлено")
        return
    ok = send_to_chat(webhook_url, message)
    if ok:
        mark_reported(new_items)
        logging.info(f"Звіт надіслано ({len(new_items)} items), state оновлено")
    else:
        logging.error("Webhook fail — state НЕ оновлено, спробуємо завтра")


if __name__ == "__main__":
    main()
