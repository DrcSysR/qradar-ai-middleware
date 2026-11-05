"""cortex_endpoint_cleanup.py — видалення з консолі Cortex XDR ендпоінтів, що довго мовчать.

Навіщо: ендпоінти, які не виходили на зв'язок N днів і більше (за замовчуванням 15; last_seen <= now − N днів), засмічують
Endpoint Administration і тримають ліцензії. Сам Cortex видаляє їх лише через 180 днів
«Connection Lost». Цей джоб робить те саме раніше, через Public API:

  1. `POST /public_api/v1/endpoints/get_endpoint` з фільтром `last_seen <= now - N днів`
     (сторінки по 100) — кандидати;
  2. локальні запобіжники: регекси імен (`cortex_xdr_cleanup_exclude_hostnames`), групи
     (`cortex_xdr_cleanup_exclude_groups`), типи (`cortex_xdr_cleanup_exclude_types`,
     напр. AGENT_TYPE_SERVER), ізольовані хости (`cortex_xdr_cleanup_skip_isolated`),
     стеля на один прогін (`cortex_xdr_cleanup_max_per_run`);
  3. `POST /public_api/v1/endpoints/delete` з `endpoint_id_list` (до 1000 за запит);
  4. контрольне читання тих самих id — скільки лишилось;
  5. запис у таблицю `cortex_endpoint_deleted` в ai_state.db + звіт у Google Chat (webhook
     `cortex_xdr_webhook_url`, інакше `falcon_pua_webhook_url`);
  6. блок «повернулися після видалення»: раніше видалені записи звіряються з консоллю за
     endpoint_id (Cortex відновив запис) і за ім'ям хоста (новий id після переустановки);
     знайдені потрапляють у звіт і позначаються `returned_ts`/`returned_as`.

Видалення з консолі НЕ деінсталює агент: якщо хост повернеться, агент зареєструється як новий
запис (і ліцензію візьме знову). Тому операція безпечна для живих машин, а стан «видалено»
у Cortex зворотний лише через перепідключення.

Ключі API: для читання — той самий read-only ключ, що й у cortex_xdr_scan.py
(`cortex_xdr_api_key_id`/`cortex_xdr_api_key`). Для видалення потрібен окремий ключ з роллю,
яка має право Endpoint Administration → Delete (`cortex_xdr_admin_api_key_id` /
`cortex_xdr_admin_api_key`, той самий рівень `cortex_xdr_api_security`). Без admin-ключа
скрипт працює лише в режимі dry-run.

Безпека за замовчуванням: `cortex_xdr_cleanup_dry_run` = true у схемі — поки в config.json не
поставити false (або не запустити з `--apply`), скрипт тільки звітує. `--dry-run` примусово
вимикає видалення незалежно від конфігу. `--days N` перекриває поріг для одного прогону.

Запускається через systemd timer (`cortex_endpoint_cleanup.timer`, щодня 10:00). Lock —
fcntl на cortex_endpoint_cleanup.lock, лог — cortex_endpoint_cleanup.log.
Секрети (ключі, webhook) — тільки в config.json (gitignored), НЕ комітити.
"""
import fcntl
import json
import logging
import os
import re
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone

import requests

import cortex_xdr_scan as cx

BASE_DIR = "/opt/qradar-middleware"
DB_PATH = os.path.join(BASE_DIR, "ai_state.db")
LOCK_FILE = os.path.join(BASE_DIR, "cortex_endpoint_cleanup.lock")
LOG_FILE = os.path.join(BASE_DIR, "cortex_endpoint_cleanup.log")

DELETE_BATCH = 1000  # стеля API на один запит endpoints/delete

DEFAULTS = {
    "cortex_xdr_cleanup_days": 15,
    "cortex_xdr_cleanup_dry_run": True,
    "cortex_xdr_cleanup_max_per_run": 100,
    "cortex_xdr_cleanup_exclude_hostnames": [],
    "cortex_xdr_cleanup_exclude_groups": [],
    "cortex_xdr_cleanup_exclude_types": [],
    "cortex_xdr_cleanup_skip_isolated": True,
    "cortex_xdr_cleanup_report_title": "🧹 Cortex XDR — прибирання мовчазних ендпоінтів",
    "cortex_xdr_admin_api_key_id": "",
    "cortex_xdr_admin_api_key": "",
}

# force=True: імпорт cortex_xdr_scan уже налаштував root-логер на cortex_xdr_scan.log —
# без force наш basicConfig був би no-op і лог прибирання їхав би в чужий файл.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
    force=True,
)


def cfg(config: dict, key: str):
    return config.get(key, DEFAULTS[key])


def admin_config(config: dict) -> dict | None:
    """Копія конфігу, де ключ API замінено на admin-ключ (для endpoints/delete)."""
    key_id = str(cfg(config, "cortex_xdr_admin_api_key_id")).strip()
    key = str(cfg(config, "cortex_xdr_admin_api_key")).strip()
    if not (key_id and key):
        return None
    return {**config, "cortex_xdr_api_key_id": key_id, "cortex_xdr_api_key": key}


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cortex_endpoint_deleted (
                endpoint_id TEXT NOT NULL,
                endpoint_name TEXT,
                endpoint_status TEXT,
                endpoint_type TEXT,
                last_seen_ts DATETIME,
                silent_days REAL,
                ip TEXT,
                users TEXT,
                groups TEXT,
                deleted_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                run_id TEXT,
                returned_ts DATETIME,
                returned_as TEXT,
                PRIMARY KEY (endpoint_id, deleted_ts)
            )
            """
        )
        cols = {r[1] for r in conn.execute("PRAGMA table_info(cortex_endpoint_deleted)")}
        for col in ("returned_ts DATETIME", "returned_as TEXT"):
            if col.split()[0] not in cols:
                conn.execute(f"ALTER TABLE cortex_endpoint_deleted ADD COLUMN {col}")


def sqlite_ts_ms(ts: str) -> int:
    """'YYYY-MM-DD HH:MM:SS' (CURRENT_TIMESTAMP у SQLite, UTC) -> мс епохи; 0 якщо не розібрати."""
    try:
        return int(datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp() * 1000)
    except (TypeError, ValueError):
        return 0


def ts_iso(ms) -> str:
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        return "?"


def post(config: dict, path: str, request_data: dict, timeout: int):
    """Один POST у Public API. Повертає reply або None при помилці (все залоговано)."""
    url = f"https://{cx.api_host(config)}{path}"
    try:
        # Заголовки щоразу нові: nonce/timestamp у Advanced одноразові.
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


def fetch_endpoints(config: dict, filters: list, cap: int = 20000) -> list | None:
    """Усі ендпоінти за фільтром (сторінки по 100). None — помилка API."""
    page = 100
    timeout = int(cx.cfg(config, "cortex_xdr_api_timeout_seconds"))
    out: list = []
    while len(out) < cap:
        reply = post(config, "/public_api/v1/endpoints/get_endpoint", {
            "filters": filters,
            "search_from": len(out),
            "search_to": len(out) + page,
            "sort": {"field": "last_seen", "keyword": "asc"},
        }, timeout)
        if reply is None:
            return None
        batch = reply.get("endpoints") or []
        out.extend(batch)
        if len(batch) < page or len(out) >= int(reply.get("total_count") or 0):
            break
    return out[:cap]


def fetch_silent(config: dict, days: float) -> list | None:
    cutoff = int((time.time() - days * 86400) * 1000)
    eps = fetch_endpoints(config, [{"field": "last_seen", "operator": "lte", "value": cutoff}])
    if eps is None:
        return None
    # Фільтр API перевіряємо ще й локально — щоб жодна зміна семантики на боці Cortex
    # не перетворила «старші за N днів» на «усі».
    return [e for e in eps if e.get("last_seen") and int(e["last_seen"]) <= cutoff]


def apply_guards(eps: list, config: dict) -> tuple[list, dict]:
    """Локальні запобіжники. Повертає (кандидати, статистика пропусків)."""
    name_res = [re.compile(p, re.I) for p in cfg(config, "cortex_xdr_cleanup_exclude_hostnames") or []]
    groups = {str(g).lower() for g in cfg(config, "cortex_xdr_cleanup_exclude_groups") or []}
    types = {str(t).upper() for t in cfg(config, "cortex_xdr_cleanup_exclude_types") or []}
    skip_isolated = bool(cfg(config, "cortex_xdr_cleanup_skip_isolated"))
    cap = int(cfg(config, "cortex_xdr_cleanup_max_per_run"))

    stats = {"hostname": 0, "group": 0, "type": 0, "isolated": 0, "cap": 0}
    keep = []
    for e in eps:
        name = str(e.get("endpoint_name") or "")
        if any(r.search(name) for r in name_res):
            stats["hostname"] += 1
            continue
        if groups and any(str(g).lower() in groups for g in (e.get("group_name") or [])):
            stats["group"] += 1
            continue
        if types and str(e.get("endpoint_type") or "").upper() in types:
            stats["type"] += 1
            continue
        if skip_isolated and str(e.get("is_isolated") or "").upper() not in ("", "AGENT_UNISOLATED"):
            stats["isolated"] += 1
            continue
        keep.append(e)
    # Найдавніші — першими; решта дочекається наступного прогону.
    keep.sort(key=lambda e: int(e.get("last_seen") or 0))
    if len(keep) > cap:
        stats["cap"] = len(keep) - cap
        keep = keep[:cap]
    return keep, stats


def delete_endpoints(admin_cfg: dict, ids: list) -> bool:
    timeout = int(cx.cfg(admin_cfg, "cortex_xdr_api_timeout_seconds"))
    for i in range(0, len(ids), DELETE_BATCH):
        chunk = ids[i:i + DELETE_BATCH]
        reply = post(admin_cfg, "/public_api/v1/endpoints/delete", {
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": chunk}],
        }, timeout)
        if reply is not True:
            logging.error(f"endpoints/delete: відповідь {reply!r} для {len(chunk)} id — зупиняюсь")
            return False
        logging.info(f"endpoints/delete OK: {len(chunk)} id")
    return True


def still_present(config: dict, ids: list) -> list | None:
    """Контрольне читання після видалення: які з id ще віддає get_endpoint."""
    left = []
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        eps = fetch_endpoints(config, [{"field": "endpoint_id_list", "operator": "in", "value": chunk}])
        if eps is None:
            return None
        left.extend(e.get("endpoint_id") for e in eps)
    return left


def find_returned(config: dict) -> list | None:
    """Хости з cortex_endpoint_deleted (ще не позначені як повернуті), які знову є в консолі.

    Два випадки: той самий endpoint_id (Cortex відновив запис у 90-денному вікні) або те саме
    ім'я з новим endpoint_id (переустановка / cytool reconnect після вичищення запису).
    Повертає список {row, endpoint, how} або None при помилці API.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(
            "SELECT endpoint_id, endpoint_name, deleted_ts FROM cortex_endpoint_deleted "
            "WHERE returned_ts IS NULL")]
    if not rows:
        return []
    by_id = {r["endpoint_id"]: r for r in rows}
    by_name = {}
    for r in rows:
        if r.get("endpoint_name"):
            by_name.setdefault(r["endpoint_name"].lower(), r)
    found: dict = {}
    ids = list(by_id)
    for i in range(0, len(ids), 100):
        eps = fetch_endpoints(config, [{"field": "endpoint_id_list", "operator": "in", "value": ids[i:i + 100]}])
        if eps is None:
            return None
        for e in eps:
            if str(e.get("endpoint_status") or "").upper() in ("", "UNINSTALLED") or not e.get("last_seen"):
                continue
            r = by_id.get(e.get("endpoint_id"))
            if r and int(e["last_seen"]) > sqlite_ts_ms(r["deleted_ts"]):
                found[r["endpoint_id"]] = {"row": r, "endpoint": e, "how": "same_id"}
    names = [n for n, r in by_name.items() if r["endpoint_id"] not in found]
    for i in range(0, len(names), 100):
        eps = fetch_endpoints(config, [{"field": "hostname", "operator": "in", "value": names[i:i + 100]}])
        if eps is None:
            return None
        for e in eps:
            r = by_name.get(str(e.get("endpoint_name") or "").lower())
            if not r or r["endpoint_id"] in found or e.get("endpoint_id") == r["endpoint_id"]:
                continue
            if str(e.get("endpoint_status") or "").upper() in ("", "UNINSTALLED") or not e.get("last_seen"):
                continue
            if int(e["last_seen"]) > sqlite_ts_ms(r["deleted_ts"]):
                found[r["endpoint_id"]] = {"row": r, "endpoint": e, "how": "new_id"}
    return list(found.values())


def mark_returned(items: list) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        for it in items:
            conn.execute(
                "UPDATE cortex_endpoint_deleted SET returned_ts = CURRENT_TIMESTAMP, returned_as = ? "
                "WHERE endpoint_id = ? AND deleted_ts = ?",
                (f"{it['how']}:{it['endpoint'].get('endpoint_id')}", it["row"]["endpoint_id"], it["row"]["deleted_ts"]),
            )


def record_deleted(eps: list, run_id: str, now_ms: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        for e in eps:
            ls = int(e.get("last_seen") or 0)
            conn.execute(
                """
                INSERT OR REPLACE INTO cortex_endpoint_deleted
                (endpoint_id, endpoint_name, endpoint_status, endpoint_type, last_seen_ts,
                 silent_days, ip, users, groups, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (e.get("endpoint_id"), e.get("endpoint_name"), e.get("endpoint_status"),
                 e.get("endpoint_type"), ts_iso(ls), round((now_ms - ls) / 86400000, 1),
                 ",".join(e.get("ip") or []), ",".join(e.get("users") or []),
                 ",".join(e.get("group_name") or []), run_id),
            )


def describe(e: dict, now_ms: int) -> str:
    ls = int(e.get("last_seen") or 0)
    days = (now_ms - ls) / 86400000
    ip = ",".join(e.get("ip") or []) or "—"
    users = ",".join(e.get("users") or []) or "—"
    return (f"{e.get('endpoint_name') or '?'} ({e.get('endpoint_status') or '?'}, "
            f"{str(e.get('endpoint_type') or '').replace('AGENT_TYPE_', '').lower() or '?'}) — "
            f"мовчить {days:.0f} д, останній контакт {ts_iso(ls)}, ip {ip}, user {users}")


def describe_returned(it: dict) -> str:
    e, r = it["endpoint"], it["row"]
    how = ("відновлено старий запис" if it["how"] == "same_id"
           else f"новий запис (переустановка/reconnect), id {e.get('endpoint_id')}")
    ip = ",".join(e.get("ip") or []) or "—"
    return (f"{r.get('endpoint_name') or e.get('endpoint_name') or '?'} — видалено {r['deleted_ts']} UTC, "
            f"знову на зв'язку {ts_iso(e.get('last_seen'))} ({e.get('endpoint_status')}, ip {ip}); {how}")


def build_chat_message(title: str, deleted: list, left: list, stats: dict, days: float,
                       now_ms: int, dry_run: bool, returned: list | None = None) -> dict:
    head = "DRY-RUN: видалили б" if dry_run else "видалено"
    lines = [f"*{title}*",
             f"_{head} {len(deleted)} ендпоінтів без зв'язку понад {days:g} д_"]
    if left:
        lines.append(f"⚠️ після видалення консоль ще віддає {len(left)} id — перевірити вручну")
    skipped = {k: v for k, v in stats.items() if v}
    if skipped:
        lines.append("_пропущено запобіжниками: " + ", ".join(f"{k}={v}" for k, v in skipped.items()) + "_")
    lines.append("")
    for e in deleted[:60]:
        lines.append(f"  • {describe(e, now_ms)}")
    if len(deleted) > 60:
        lines.append(f"  …та ще {len(deleted) - 60}")
    if returned:
        lines += ["", f"*↩️ Повернулися після видалення: {len(returned)}*"]
        for it in returned[:60]:
            lines.append(f"  • {describe_returned(it)}")
        if len(returned) > 60:
            lines.append(f"  …та ще {len(returned) - 60}")
    return {"text": "\n".join(lines)}


def main() -> None:
    config = cx.load_config()
    run_id = uuid.uuid4().hex[:12]
    args = sys.argv[1:]

    dry_run = bool(cfg(config, "cortex_xdr_cleanup_dry_run"))
    if "--apply" in args:
        dry_run = False
    if "--dry-run" in args:
        dry_run = True
    days = float(cfg(config, "cortex_xdr_cleanup_days"))
    if "--days" in args:
        days = float(args[args.index("--days") + 1])
    if days < 1:
        logging.error(f"cortex_xdr_cleanup_days={days} — поріг менше 1 дня не допускається")
        sys.exit(2)

    if not (cx.cfg(config, "cortex_xdr_api_fqdn") and cx.cfg(config, "cortex_xdr_api_key_id")
            and cx.cfg(config, "cortex_xdr_api_key")):
        logging.error("Немає cortex_xdr_api_fqdn / cortex_xdr_api_key_id / cortex_xdr_api_key у config.json")
        sys.exit(2)
    admin_cfg = admin_config(config)
    if not dry_run and admin_cfg is None:
        logging.error("Немає cortex_xdr_admin_api_key_id / cortex_xdr_admin_api_key — видалення неможливе, "
                      "запускаю як dry-run")
        dry_run = True
    webhook_url = config.get("cortex_xdr_webhook_url") or config.get("falcon_pua_webhook_url")

    init_db()
    lock_fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logging.warning("Previous cortex_endpoint_cleanup still running. Skipping this run.")
        sys.exit(0)

    logging.info(f"=== Cortex endpoint cleanup run_id={run_id} days={days:g} "
                 f"max={cfg(config, 'cortex_xdr_cleanup_max_per_run')} api={cx.api_host(config)}"
                 f"{' DRY-RUN' if dry_run else ' APPLY'} ===")

    # Блок «повернулися після видалення»: раніше видалені записи, що знову є в консолі.
    returned = find_returned(config)
    if returned is None:
        logging.error("Cortex API недоступний (звірка повернутих) — нічого не робимо")
        sys.exit(1)
    for it in returned:
        logging.info(f"returned: {describe_returned(it)}")

    silent = fetch_silent(config, days)
    if silent is None:
        logging.error("Cortex API недоступний — нічого не робимо")
        sys.exit(1)
    now_ms = int(time.time() * 1000)
    candidates, stats = apply_guards(silent, config)
    logging.info(f"silent>{days:g}d={len(silent)} candidates={len(candidates)} skipped={stats}")
    for e in candidates:
        logging.info(f"{'[dry-run] ' if dry_run else ''}delete: {describe(e, now_ms)}")

    if not candidates and not returned:
        logging.info("Кандидатів і повернутих немає — звіт не шлемо")
        return

    left: list = []
    if not dry_run:
        ids = [e["endpoint_id"] for e in candidates if e.get("endpoint_id")]
        if not delete_endpoints(admin_cfg, ids):
            logging.error("Видалення не підтверджено API — state не оновлено, звіт не шлемо")
            sys.exit(1)
        time.sleep(3)
        left = still_present(config, ids) or []
        if left:
            logging.warning(f"Після видалення ще присутні {len(left)} id: {left[:10]}")
        record_deleted(candidates, run_id, now_ms)
        logging.info(f"Видалено {len(candidates)}, state оновлено")

    message = build_chat_message(cfg(config, "cortex_xdr_cleanup_report_title"), candidates, left,
                                 stats, days, now_ms, dry_run, returned)
    if dry_run:
        print(message["text"])
        logging.info("DRY-RUN: нічого не видалено, звіт не надіслано, повернуті не позначено")
        return
    if not webhook_url:
        logging.warning("Немає webhook у config.json — звіт лише в лог")
        mark_returned(returned)
        return
    if cx.send_to_chat(webhook_url, message):
        # Повернутих позначаємо лише після успішного звіту — інакше покажемо наступного разу.
        mark_returned(returned)
        logging.info(f"Звіт надіслано (видалено {len(candidates)}, повернулось {len(returned)})")
    else:
        logging.error("Webhook fail — видалення вже виконано, звіт лише в лог")


if __name__ == "__main__":
    main()
