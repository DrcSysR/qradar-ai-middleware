"""Google Chat-бот «Cortex / QRadar»: звіти за кнопками замість розсилки в групу за розкладом.

Версія 1 — ЛИШЕ ЧИТАННЯ: меню-картка і звіти (кейси Cortex на перегляд, що закрито автоматично, які
ендпоінти видалено з консолі, відкриті офенси QRadar, що закрив тріаж, останній звіт 09:30). Звіт нічого
не змінює (жодного закриття, жодних записів у стан дедуплікації). Дії-записи (закрити, дорозслідувати
Vertex-ом) — окремий крок, не тут.

Транспорт — HTTP-ендпоінт Chat-застосунку (проєкт ibm-qradar-283907): nginx2 публікує
https://qrcr.modern-expo.ua/chat → цей сервіс на mdlwr01 (TLS, лише з довіреного проксі). Кожен запит —
OIDC-токен Google (chat_auth.verify_chat_token) + членство в групі `cortexbot_allowed_group`
(soc@modern-expo.com, Cloud Identity; збій перевірки = відмова, запасного списку немає). Відповіді на кнопки віддаємо одразу
(«⏳»), сам звіт прилітає окремим(и) повідомленням(и) через Chat API від імені застосунку (SA cortexbot,
scope chat.bot) — Cortex API / QRadar повільніші за синхронний таймаут Chat.

Модуль самодостатній: cortex_xdr_scan / cortex_incident_triage НЕ імпортуються — вони при імпорті
відкривають root-овий лог-файл, а сервіс працює під qmiddleware.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import string
import threading
import time
from logging.handlers import RotatingFileHandler

import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import chat_auth

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "ai_state.db")
LAST_REPORT = os.path.join(BASE_DIR, "cortex_last_report.txt")
LOG_FILE = os.path.join(BASE_DIR, "cortex_bot.log")

_h = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3) if os.access(BASE_DIR, os.W_OK) \
    else logging.StreamHandler()
logging.basicConfig(level=logging.INFO, handlers=[_h], format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger("cortex_bot")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
SPACE_RE = re.compile(r"^spaces/[A-Za-z0-9_-]{1,64}$")
THREAD_RE = re.compile(r"^spaces/[A-Za-z0-9_-]{1,64}/threads/[A-Za-z0-9_-]{1,64}$")
CHAT_SCOPE = "https://www.googleapis.com/auth/chat.bot"
CHAT_CHUNK = 3500

DEFAULTS = {
    "cortexbot_chat_audience": "https://qrcr.modern-expo.ua/chat",
    "cortexbot_trusted_proxies": ["172.17.61.166"],
    # Доступ — ЛИШЕ члени цієї групи (Cloud Identity, транзитивно); запасного списку немає, збій перевірки = відмова.
    "cortexbot_allowed_group": "soc@modern-expo.com",
    "cortexbot_allowed_domain": "modern-expo.com",
    # Ключ SA з правом Groups Reader у Workspace (той самий, що в netdiag-бота), щоб не видавати нову роль.
    "cortexbot_ci_key_file": os.path.join(BASE_DIR, "netdiag_sa.json"),
    "cortexbot_sa_key_file": os.path.join(BASE_DIR, "cortexbot_sa.json"),
    "cortexbot_rate_per_minute": 12,
    "cortexbot_review_hours": 72,
    "cortexbot_review_max": 25,
    "cortexbot_qradar_min_magnitude": 6,
    "cortexbot_qradar_hours": 24,
}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def conf() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE, encoding="utf-8") as fh:
            for k, v in json.load(fh).items():
                cfg[k] = v
    except (OSError, ValueError) as e:
        log.error(f"config.json не читається: {e}")
    return cfg


def split_text(text: str, limit: int = CHAT_CHUNK) -> list:
    parts, cur = [], ""
    for line in text.split("\n"):
        line = line[:limit]
        if cur and len(cur) + len(line) + 1 > limit:
            parts.append(cur)
            cur = line
        else:
            cur = f"{cur}\n{line}" if cur else line
    if cur.strip():
        parts.append(cur)
    return parts


# ============================================================================ авторизація
def authorized(cfg: dict, email: str) -> bool:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email) or not email.endswith("@" + str(cfg.get("cortexbot_allowed_domain")).lower()):
        return False
    return chat_auth.in_group(cfg.get("cortexbot_ci_key_file"), email, cfg.get("cortexbot_allowed_group"))


_rate: dict = {}
_rate_lock = threading.Lock()


def rate_ok(cfg: dict, email: str) -> bool:
    now = time.monotonic()
    limit = int(cfg.get("cortexbot_rate_per_minute"))
    with _rate_lock:
        q = [t for t in _rate.get(email, []) if now - t < 60]
        if len(q) >= limit:
            _rate[email] = q
            return False
        q.append(now)
        _rate[email] = q
        return True


# ============================================================================ Chat API (асинхронні відповіді)
_chat_session = None
_chat_lock = threading.Lock()


def _chat(cfg: dict):
    global _chat_session
    with _chat_lock:
        if _chat_session is None:
            from google.auth.transport.requests import AuthorizedSession
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_file(cfg.get("cortexbot_sa_key_file"), scopes=[CHAT_SCOPE])
            _chat_session = AuthorizedSession(creds)
        return _chat_session


def chat_post(cfg: dict, space: str, text: str, thread: str = "") -> bool:
    if not SPACE_RE.match(space or ""):
        log.error("chat_post: некоректний space")
        return False
    msg: dict = {"text": text}
    params = {}
    if thread and THREAD_RE.match(thread):
        msg["thread"] = {"name": thread}
        params["messageReplyOption"] = "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
    for attempt in range(1, 4):
        try:
            r = _chat(cfg).post(f"https://chat.googleapis.com/v1/{space}/messages", params=params, json=msg, timeout=20)
        except Exception as e:
            log.error(f"chat_post: {type(e).__name__}")
            return False
        if r.status_code == 429 and attempt < 3:
            time.sleep(3 * attempt)
            continue
        if r.status_code >= 300:
            log.error(f"chat_post HTTP {r.status_code}: {r.text[:300]}")
            return False
        return True
    return False


def deliver(cfg: dict, space: str, thread: str, text: str) -> None:
    parts = split_text(text)
    for i, p in enumerate(parts, 1):
        body = p if len(parts) == 1 else f"{p}\n_(частина {i}/{len(parts)})_"
        if not chat_post(cfg, space, body, thread):
            log.error(f"deliver: частина {i}/{len(parts)} не доставлена")
            return
        if i < len(parts):
            time.sleep(1.3)   # ~1 повідомлення/с на простір


# ============================================================================ Cortex / QRadar: читання
def cortex_headers(cfg: dict) -> dict:
    key_id, key = str(cfg.get("cortex_xdr_api_key_id", "")), str(cfg.get("cortex_xdr_api_key", ""))
    if str(cfg.get("cortex_xdr_api_security", "advanced")).lower() == "standard":
        return {"x-xdr-auth-id": key_id, "Authorization": key, "Content-Type": "application/json"}
    nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
    ts = str(int(time.time() * 1000))
    return {"x-xdr-auth-id": key_id, "Authorization": hashlib.sha256(f"{key}{nonce}{ts}".encode()).hexdigest(),
            "Content-Type": "application/json", "x-xdr-timestamp": ts, "x-xdr-nonce": nonce}


def cortex_host(cfg: dict) -> str:
    fqdn = str(cfg.get("cortex_xdr_api_fqdn", "")).strip().removeprefix("https://").strip("/")
    return fqdn if fqdn.startswith("api-") else f"api-{fqdn}"


def cortex_incidents(cfg: dict, hours: float):
    since = int((time.time() - hours * 3600) * 1000)
    out, frm = [], 0
    while frm < 1000:
        r = requests.post(f"https://{cortex_host(cfg)}/public_api/v1/incidents/get_incidents", headers=cortex_headers(cfg),
                          timeout=60, json={"request_data": {
                              "filters": [{"field": "status", "operator": "in", "value": ["new"]},
                                          {"field": "creation_time", "operator": "gte", "value": since}],
                              "search_from": frm, "search_to": frm + 100,
                              "sort": {"field": "creation_time", "keyword": "desc"}}})
        r.raise_for_status()
        reply = r.json().get("reply") or {}
        batch = reply.get("incidents") or []
        out += batch
        if len(batch) < 100 or len(out) >= int(reply.get("total_count") or 0):
            break
        frm += 100
    return out


def db(sql: str, args: tuple = ()) -> list:
    with sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=10) as conn:
        return conn.execute(sql, args).fetchall()


def db_safe(sql: str, args: tuple = ()) -> list:
    try:
        return db(sql, args)
    except sqlite3.Error as e:
        log.warning(f"db: {e}")
        return []


SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1}
VERDICT_ICON = {"benign": "🟢 схоже на доброякісне", "suspicious": "🟠 підозріло",
                "malicious": "🔴 ймовірно шкідливе", "unclear": "⚪ недостатньо даних"}


def q(s) -> str:
    """Текст із зовнішніх систем у повідомлення: без розмітки, що ламає посилання/жирний."""
    return str(s or "").replace("<", "‹").replace(">", "›").replace("*", "·").replace("`", "'").replace("\n", " ")


def report_review(cfg: dict) -> str:
    inc = cortex_incidents(cfg, float(cfg.get("cortexbot_review_hours")))
    ai = {str(r[0]): r for r in db_safe("SELECT incident_id, verdict, summary FROM cortex_incident_ai")}
    noted = {str(r[0]) for r in db_safe("SELECT incident_id FROM cortex_incident_noted")}
    inc.sort(key=lambda i: -SEV.get(str(i.get("severity") or "").lower(), 0))
    mx = int(cfg.get("cortexbot_review_max"))
    lines = [f"*Cortex: відкриті кейси (new) за {cfg.get('cortexbot_review_hours')} год — {len(inc)}*"]
    for i in inc[:mx]:
        iid = str(i.get("incident_id"))
        url = i.get("xdr_url")
        ref = f"<{url}|#{iid}>" if url else f"#{iid}"
        hosts = ", ".join(h.split(":")[-1] if h.startswith("NO_HOST") else h.split(":")[0] for h in (i.get("hosts") or [])[:3])
        lines.append(f"• {ref} [{q(i.get('severity'))}] {q(i.get('description'))[:90]}{' — ' + q(hosts) if hosts else ''}")
        a = ai.get(iid)
        if a:
            tail = " — розбір у Notes кейсу" if iid in noted else f": {q(a[2])[:200]}"
            lines.append(f"   🤖 {VERDICT_ICON.get(a[1], q(a[1]))}{tail}")
    if len(inc) > mx:
        lines.append(f"… і ще {len(inc) - mx}")
    if not inc:
        lines.append("Відкритих кейсів немає.")
    return "\n".join(lines)


def report_closed(cfg: dict, days: int = 7) -> str:
    rows = db_safe("SELECT incident_id, rule, status, description, severity, closed_ts FROM cortex_incident_closed "
                   "WHERE closed_ts >= datetime('now', ?) ORDER BY closed_ts DESC", (f"-{days} days",))
    by_rule: dict = {}
    for r in rows:
        by_rule[r[1]] = by_rule.get(r[1], 0) + 1
    lines = [f"*Cortex: закрито автотріажем за {days} дн — {len(rows)}* ({', '.join(f'{k}: {v}' for k, v in by_rule.items()) or '—'})"]
    for r in rows[:30]:
        lines.append(f"• #{r[0]} [{q(r[4])}] {q(r[3])[:80]} — {q(r[1])} ({str(r[5])[:16]} UTC)")
    if len(rows) > 30:
        lines.append(f"… і ще {len(rows) - 30}")
    return "\n".join(lines)


def report_deleted(cfg: dict, days: int = 14) -> str:
    rows = db_safe("SELECT endpoint_name, ip, silent_days, deleted_ts, returned_ts, returned_as FROM cortex_endpoint_deleted "
                   "WHERE deleted_ts >= datetime('now', ?) ORDER BY deleted_ts DESC", (f"-{days} days",))
    back = [r for r in rows if r[4]]
    lines = [f"*Cortex: видалено з консолі (мовчали 15+ днів) за {days} дн — {len(rows)}; повернулись: {len(back)}*"]
    for r in rows[:40]:
        lines.append(f"• {q(r[0])} ({q(r[1])}) мовчав {int(r[2] or 0)} дн, видалено {str(r[3])[:16]} UTC"
                     f"{' ↩ повернувся' + (' як ' + q(r[5]) if r[5] else '') if r[4] else ''}")
    if len(rows) > 40:
        lines.append(f"… і ще {len(rows) - 40}")
    return "\n".join(lines)


def qradar_open(cfg: dict):
    base = str(cfg.get("qradar_url") or "").rstrip("/")
    token = cfg.get("qradar_token")
    since = int((time.time() - float(cfg.get("cortexbot_qradar_hours")) * 3600) * 1000)
    r = requests.get(f"{base}/api/siem/offenses", verify=False, timeout=90,
                     headers={"SEC": token, "Accept": "application/json", "Version": "19.0", "Range": "items=0-1999"},
                     params={"filter": f'status="OPEN" and magnitude>={int(cfg.get("cortexbot_qradar_min_magnitude"))} '
                                       f'and last_updated_time>{since}',
                             "fields": "id,description,offense_source,magnitude,assigned_to"})
    r.raise_for_status()
    return base, r.json()


def report_qr_open(cfg: dict) -> str:
    base, offs = qradar_open(cfg)
    offs.sort(key=lambda o: (-int(o.get("magnitude") or 0), -int(o.get("id") or 0)))
    lines = [f"*QRadar: відкриті офенси magnitude ≥ {cfg.get('cortexbot_qradar_min_magnitude')} за {cfg.get('cortexbot_qradar_hours')} год — {len(offs)}*"]
    for o in offs[:30]:
        link = f"<{base}/console/qradar.jsp?appName=Sem&pageId=OffenseSummary&summaryId={o['id']}|#{o['id']}>"
        lines.append(f"• {link} [m{o.get('magnitude')}] {q(o.get('description'))[:80]} — {q(o.get('offense_source'))}"
                     f"{' 👤 ' + q(o.get('assigned_to')) if o.get('assigned_to') else ''}")
    if len(offs) > 30:
        lines.append(f"… і ще {len(offs) - 30}")
    return "\n".join(lines)


def report_qr_triage(cfg: dict) -> str:
    rows = db_safe("SELECT COALESCE(verdict,''), COUNT(*), ROUND(AVG(score),2), MAX(score) FROM offenses "
                   "WHERE status='PROCESSED' AND last_updated >= datetime('now','-1 day') GROUP BY 1 ORDER BY 2 DESC")
    model = [r for r in rows if r[0]]
    det = sum(r[1] for r in rows if not r[0])      # без вердикту = close_on_empty: AQL відфільтрував усе відоме
    n_model = sum(r[1] for r in model)
    closed = db_safe("SELECT COUNT(*) FROM offenses WHERE status='PROCESSED' AND verdict<>'' AND score<=0.6 "
                     "AND last_updated >= datetime('now','-1 day')")
    esc = db_safe("SELECT COUNT(*) FROM offenses WHERE escalated=1 AND last_updated >= datetime('now','-1 day')")
    lines = [f"*QRadar за добу: оброблено {n_model + det}* — моделлю {n_model} (з них score ≤ 0.6 → автозакриття: "
             f"{closed[0][0] if closed else '?'}; ескалація на Vertex: {esc[0][0] if esc else '?'}), "
             f"детермінованим фільтром AQL без моделі {det}"]
    for r in model[:15]:
        lines.append(f"• {q(r[0])}: {r[1]} (середній score {r[2]}, максимум {r[3]})")
    return "\n".join(lines)


def report_last(cfg: dict) -> str:
    try:
        with open(LAST_REPORT, encoding="utf-8") as fh:
            return fh.read()[:60000]
    except OSError:
        return "Останній звіт ще не збережено."


REPORTS = {
    "r_review": ("кейси Cortex на перегляд", report_review),
    "r_closed": ("закрито автотріажем (Cortex)", report_closed),
    "r_deleted": ("видалені ендпоінти Cortex", report_deleted),
    "r_qr_open": ("відкриті офенси QRadar", report_qr_open),
    "r_qr_triage": ("що розібрала модель (QRadar)", report_qr_triage),
    "r_last": ("останній звіт 09:30", report_last),
}


# ============================================================================ картки
def button(text: str, fn: str, icon: str | None = None, filled: bool = False) -> dict:
    b = {"text": text, "onClick": {"action": {"function": fn}}}
    if icon:
        b["icon"] = {"materialIcon": {"name": icon}}
    if filled:
        b["type"] = "FILLED"
    return b


def home() -> dict:
    return {"fallbackText": "Меню Cortex / QRadar",
            "cardsV2": [{"cardId": "home", "card": {
                "header": {"title": "Cortex XDR · QRadar", "subtitle": "звіти за запитом — без розсилки за розкладом"},
                "sections": [
                    {"header": "Cortex XDR", "widgets": [{"buttonList": {"buttons": [
                        button("Кейси на перегляд", "r_review", "assignment", True),
                        button("Закрито автоматично", "r_closed", "task_alt"),
                        button("Видалені ендпоінти", "r_deleted", "delete")]}}]},
                    {"header": "QRadar", "widgets": [{"buttonList": {"buttons": [
                        button("Відкриті офенси", "r_qr_open", "shield", True),
                        button("Що розібрала модель", "r_qr_triage", "psychology")]}}]},
                    {"widgets": [{"buttonList": {"buttons": [button("Останній звіт 09:30", "r_last", "description")]}},
                                 {"textParagraph": {"text": "Лише перегляд: ці кнопки нічого не закривають і не змінюють."}}]},
                ]}}]}


# ============================================================================ обробка подій
_bg: set = set()


def spawn(coro) -> None:
    t = asyncio.ensure_future(coro)
    _bg.add(t)
    t.add_done_callback(_bg.discard)


async def run_report(cfg: dict, fn: str, space: str, thread: str, email: str, aid: str) -> None:
    title, func = REPORTS[fn]
    try:
        text = await asyncio.to_thread(func, cfg)
        ok = await asyncio.to_thread(deliver, cfg, space, thread, text)
        log.info(f"[#{aid}] report {fn} user={email} chars={len(text)} done")
    except Exception as e:
        log.exception(f"[#{aid}] report {fn} failed: {e}")
        await asyncio.to_thread(chat_post, cfg, space, f"⚠️ Звіт «{title}» не вдався ({type(e).__name__}) — деталі в журналі бота, дія #{aid}.", thread)


def click_fn(event: dict) -> str:
    common = event.get("common") or {}
    return str(common.get("invokedFunction") or (event.get("action") or {}).get("actionMethodName") or "")


async def handle_event(cfg: dict, event: dict, email: str) -> dict:
    etype = event.get("type")
    if etype == "ADDED_TO_SPACE":
        return home()
    if etype == "MESSAGE":
        return home()          # будь-який текст → меню (v1 без вільних команд)
    if etype != "CARD_CLICKED":
        return {}
    fn = click_fn(event)
    if fn == "home":
        return {"actionResponse": {"type": "NEW_MESSAGE"}, **home()}
    if fn not in REPORTS:
        return {}
    if not rate_ok(cfg, email):
        return {"actionResponse": {"type": "NEW_MESSAGE"}, "text": "⏳ Забагато запитів — спробуйте за хвилину."}
    aid = secrets.token_hex(3)
    space = (event.get("space") or {}).get("name", "")
    thread = ((event.get("message") or {}).get("thread") or {}).get("name", "")
    log.info(f"[#{aid}] click {fn} user={email}")
    spawn(run_report(cfg, fn, space, thread, email, aid))
    return {"actionResponse": {"type": "NEW_MESSAGE"}, "text": f"🔎 Готую: {REPORTS[fn][0]}… результат прийде окремим повідомленням."}


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/chat")
async def chat(request: Request):
    cfg = conf()
    peer = request.client.host if request.client else ""
    if peer not in set(cfg.get("cortexbot_trusted_proxies")):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not await asyncio.to_thread(chat_auth.verify_chat_token, token.strip(), cfg.get("cortexbot_chat_audience")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        event = await request.json()
    except Exception:
        return JSONResponse({"error": "bad request"}, status_code=400)
    if not isinstance(event, dict):
        return JSONResponse({"error": "bad request"}, status_code=400)
    user = event.get("user") or {}
    email = (user.get("email") or "").strip().lower() if user.get("type") == "HUMAN" else ""
    if event.get("type") not in ("MESSAGE", "ADDED_TO_SPACE", "CARD_CLICKED"):
        return JSONResponse({})
    if not await asyncio.to_thread(authorized, cfg, email):
        log.info(f"deny user={email or '?'} event={event.get('type')}")
        return JSONResponse({"text": "⛔ У вас немає доступу до бота Cortex/QRadar. Зверніться до адміністратора безпеки."})
    try:
        return JSONResponse(await handle_event(cfg, event, email))
    except Exception as e:
        log.exception(f"event failed: {e}")
        return JSONResponse({"text": "⚠️ Внутрішня помилка — деталі в журналі бота."})
