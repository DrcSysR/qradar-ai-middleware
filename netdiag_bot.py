"""Google Chat-бот діагностики підключення (netdiag): користувач пише IP (або MAC) —
бот відповідає, де пристрій: Wi-Fi (точка, сигнал, стан, історія 15 хв) чи дріт (свіч,
порт, 802.1X), і що каже NPS про авторизацію. Логіка — `netdiag.py`.

Окремий процес від тріажу (`app.py`/gunicorn :5000): свої таймаути, свій перезапуск.
Запуск (systemd `netdiag-bot.service`):
  uvicorn netdiag_bot:app --host 172.17.61.225 --port 5010 --ssl-certfile … --ssl-keyfile …

Ланцюг: Google Chat → https://netdiag.modern-expo.ua/chat (nginx2, публічно — Google
дзвонить зі своїх адрес) → https://172.17.61.225:5010/chat (TLS, nginx2 перевіряє наш
самопідписаний серт за пінінгом).

Захист (кожен запит):
  1. джерело TCP — лише `netdiag_trusted_proxies` (nginx2); інакше 403;
  2. Bearer — OIDC-токен Google з aud = `netdiag_chat_audience`, iss accounts.google.com,
     email chat@system.gserviceaccount.com (режим автентифікації «HTTP endpoint URL»);
     формат JWT/kid перевіряється до будь-якої мережі, ключі Google кешуються (`_google_certs`);
  3. користувач (event.user, HUMAN) — у домені `netdiag_allowed_domain` і в групі
     `netdiag_allowed_group` (Cloud Identity, SA з роллю Groups Reader) або в списку
     `netdiag_allowed_users`. Усе інше — відмова (deny by default);
  4. ліміт запитів на користувача; IP — лише з `netdiag_allowed_networks`.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import threading
import time
from logging.handlers import RotatingFileHandler

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import netdiag
import netdiag_pa
import netdiag_ui as ui
import tracker

BASE_DIR = netdiag.BASE_DIR
LOG_FILE = os.path.join(BASE_DIR, "netdiag_bot.log")

_h = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3, encoding="utf-8") \
    if os.access(BASE_DIR, os.W_OK) else logging.StreamHandler()
logging.basicConfig(level=logging.INFO, handlers=[_h], format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("netdiag_bot")

CHAT_ISSUER = "chat@system.gserviceaccount.com"
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")
CI_API = "https://cloudidentity.googleapis.com/v1"
CI_SCOPE = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

BOT_DEFAULTS = {
    "netdiag_trusted_proxies": ["172.17.61.166"],
    "netdiag_chat_audience": "https://netdiag.modern-expo.ua/chat",
    "netdiag_allowed_domain": "modern-expo.com",
    "netdiag_allowed_group": "noc@modern-expo.com",
    "netdiag_allowed_users": [],
    "netdiag_sa_key_file": os.path.join(BASE_DIR, "netdiag_sa.json"),
    "netdiag_rate_per_minute": 6,
    "netdiag_dhcp_hours": 24,
    "netdiag_reply_budget_seconds": 26,
}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def conf() -> dict:
    cfg = netdiag.load_config()
    for k, v in BOT_DEFAULTS.items():
        if cfg.get(k) in (None, ""):
            cfg[k] = v
    return cfg


# ============================================================================ автентифікація
_greq = None


def _google_request():
    global _greq
    if _greq is None:
        import requests
        from google.auth.transport import requests as greqs
        _greq = greqs.Request(session=requests.Session())
    return _greq


# Ключі Google кешуються (Cache-Control max-age), а сміття відсіюється ДО мережі: інакше кожен
# зовнішній запит з `Bearer <будь-що>` змушував бота качати сертифікати з googleapis (DoS-підсилювач).
GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
JWT_RE = re.compile(r"^[A-Za-z0-9_-]{10,2000}\.[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,1000}$")
CERTS_MIN_REFRESH = 60          # не частіше раз на хвилину на невідомий kid (ротація ключів Google)
_certs_lock = threading.Lock()
_certs: dict[str, str] = {}
_certs_exp = 0.0
_certs_fetched = 0.0


def _jwt_kid(token: str) -> str | None:
    """kid з заголовка JWT, якщо це схоже на RS256-токен Google; інакше None (без жодних мережевих звернень)."""
    import base64
    import json
    if len(token) > 7000 or not JWT_RE.match(token):
        return None
    try:
        h = token.split(".", 1)[0]
        hdr = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    except Exception:
        return None
    if not isinstance(hdr, dict) or hdr.get("alg") != "RS256":
        return None
    kid = hdr.get("kid")
    return kid if isinstance(kid, str) and re.fullmatch(r"[A-Za-z0-9_-]{8,64}", kid) else None


def _google_certs(kid: str) -> dict[str, str]:
    """Кеш сертифікатів Google. Невідомий kid при свіжому кеші перекачує не частіше CERTS_MIN_REFRESH."""
    global _certs, _certs_exp, _certs_fetched
    with _certs_lock:
        now = time.time()
        if kid in _certs and now < _certs_exp:
            return _certs
        if now - _certs_fetched < CERTS_MIN_REFRESH:   # і після невдалої спроби — теж пауза
            return _certs
        _certs_fetched = now
        r = _google_request().session.get(GOOGLE_CERTS_URL, timeout=10)
        r.raise_for_status()
        certs = r.json()
        if not isinstance(certs, dict) or not certs:
            raise ValueError("empty certs")
        m = re.search(r"max-age=(\d+)", r.headers.get("Cache-Control", ""))
        _certs = {str(k): str(v) for k, v in certs.items()}
        _certs_exp = now + min(int(m.group(1)) if m else 3600, 6 * 3600)
        return _certs


def verify_chat_token(token: str, audience: str) -> bool:
    from google.auth import jwt
    kid = _jwt_kid(token)
    if not kid:
        log.warning("chat token rejected: malformed")
        return False
    try:
        certs = _google_certs(kid)
        if kid not in certs:
            log.warning("chat token rejected: unknown kid")
            return False
        claims = jwt.decode(token, certs={kid: certs[kid]}, audience=audience, clock_skew_in_seconds=30)
    except Exception as e:  # будь-яка помилка перевірки = відмова
        log.warning(f"chat token rejected: {type(e).__name__}")
        return False
    ok = (claims.get("iss") in GOOGLE_ISSUERS and claims.get("email") == CHAT_ISSUER
          and claims.get("email_verified", False))
    if not ok:
        log.warning("chat token rejected: issuer/email")
    return ok


_ci_lock = threading.Lock()
_ci_session = None
_group_name: dict[str, str] = {}
_member_cache: dict[tuple, tuple[bool, float]] = {}


def _ci(cfg: dict):
    global _ci_session
    with _ci_lock:
        if _ci_session is None:
            from google.auth.transport.requests import AuthorizedSession
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_file(cfg.get("netdiag_sa_key_file"), scopes=[CI_SCOPE])
            _ci_session = AuthorizedSession(creds)
        return _ci_session


def in_group(cfg: dict, email: str, group: str) -> bool:
    key = (group, email)
    now = time.monotonic()
    hit = _member_cache.get(key)
    if hit and hit[1] > now:
        return hit[0]
    try:
        s = _ci(cfg)
        if group not in _group_name:
            r = s.get(f"{CI_API}/groups:lookup", params={"groupKey.id": group}, timeout=10)
            r.raise_for_status()
            _group_name[group] = r.json()["name"]
        r = s.get(f"{CI_API}/{_group_name[group]}/memberships:checkTransitiveMembership",
                  params={"query": f"member_key_id == '{email}'"}, timeout=10)  # email провалідований regex — без лапок
        r.raise_for_status()
        member = bool(r.json().get("hasMembership"))
    except Exception as e:
        log.error(f"group check failed ({group}): {type(e).__name__}")
        return False
    _member_cache[key] = (member, now + 120)
    return member


def authorized(cfg: dict, email: str) -> bool:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        return False
    if email in {u.strip().lower() for u in cfg.get("netdiag_allowed_users") or []}:
        return True
    if not email.endswith("@" + cfg.get("netdiag_allowed_domain").lower()):
        return False
    group = (cfg.get("netdiag_allowed_group") or "").strip().lower()
    return bool(group) and EMAIL_RE.match(group) is not None and in_group(cfg, email, group)


# ============================================================================ Chat API (асинхронні відповіді)
CHAT_SCOPE = "https://www.googleapis.com/auth/chat.bot"
SPACE_RE = re.compile(r"^spaces/[A-Za-z0-9_-]{1,64}$")
THREAD_RE = re.compile(r"^spaces/[A-Za-z0-9_-]{1,64}/threads/[A-Za-z0-9_-]{1,64}$")
_chat_session = None
_bg_tasks: set = set()


def _chat(cfg: dict):
    global _chat_session
    with _ci_lock:
        if _chat_session is None:
            from google.auth.transport.requests import AuthorizedSession
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_file(cfg.get("netdiag_sa_key_file"), scopes=[CHAT_SCOPE])
            _chat_session = AuthorizedSession(creds)
        return _chat_session


def chat_post(cfg: dict, space: str, body: dict, thread: str = "") -> bool:
    """Повідомлення від імені застосунку (SA проєкту Chat app, scope chat.bot) — для відповідей,
    які не вкладаються в синхронний таймаут Chat (діалог чекає лише ~8 с)."""
    if not SPACE_RE.match(space or ""):
        log.error("chat_post: некоректний space")
        return False
    msg = {k: v for k, v in body.items() if k in ("text", "cardsV2", "fallbackText")}
    params = {}
    if thread and THREAD_RE.match(thread):
        msg["thread"] = {"name": thread}
        params["messageReplyOption"] = "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
    try:
        r = _chat(cfg).post(f"https://chat.googleapis.com/v1/{space}/messages", params=params, json=msg, timeout=20)
    except Exception as e:
        log.error(f"chat_post: {type(e).__name__}")
        return False
    if r.status_code >= 300:
        log.error(f"chat_post HTTP {r.status_code}: {r.text[:300]}")
        return False
    return True


def spawn(coro) -> None:
    t = asyncio.create_task(coro)
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)


def tag_action(body: dict, aid: str) -> dict:
    """ID дії в підзаголовок картки — щоб тред у чаті зіставлявся з рядками журналу."""
    try:
        h = body["cardsV2"][0]["card"].setdefault("header", {})
        h["subtitle"] = (h.get("subtitle", "") + f" · дія #{aid}").lstrip(" ·")
    except (KeyError, IndexError, TypeError):
        pass
    return body


async def diag_async(cfg: dict, raw: str, pa: bool, space: str, thread: str, email: str, aid: str) -> None:
    t0 = time.monotonic()
    body = tag_action(await diag_body(cfg, raw, pa), aid)
    ok = await asyncio.to_thread(chat_post, cfg, space, body, thread)
    log.info(f"[#{aid}] diag done user={email} delivered={ok} in {time.monotonic() - t0:.1f}s thread={thread or '-'}")


_rate: dict[str, list[float]] = {}


def rate_ok(cfg: dict, email: str) -> bool:
    now = time.monotonic()
    q = [t for t in _rate.get(email, []) if now - t < 60]
    if len(q) >= int(cfg.get("netdiag_rate_per_minute")):
        _rate[email] = q
        return False
    q.append(now)
    _rate[email] = q
    return True


# ============================================================================ діагностика
def _qradar(cfg: dict) -> tuple[str, dict]:
    return f"{cfg['qradar_url']}/api", {"SEC": cfg["qradar_token"], "Accept": "application/json", "Version": "20.0"}


async def run_query(cfg: dict, text: str) -> dict:
    """Повна діагностика → тіло відповіді Chat (cardsV2 + fallbackText)."""
    deadline = time.monotonic() + float(cfg.get("netdiag_reply_budget_seconds"))
    res = await asyncio.to_thread(netdiag.diagnose_fast, cfg, text)
    if res.get("error") == "no_target":
        return {"text": netdiag.render_fast(res)}
    api, headers = _qradar(cfg)
    notes: list[str] = []
    nps = None
    minutes = int(cfg.get("netdiag_nps_minutes") or 60)
    # QRadar — самопідписаний серт (як і в app.py/tracker), трафік лише в LAN
    async with httpx.AsyncClient(verify=False, timeout=20) as client:
        if not res.get("mac") and res.get("ip"):
            left = deadline - time.monotonic()
            if left > 6:
                aql = netdiag.dhcp_aql(res["ip"], None, int(cfg.get("netdiag_dhcp_hours")),
                                       cfg.get("track_dhcp_logsource") or "LinuxDHCP @ dhcp1")
                ev = await tracker.run_aql(client, api, headers, aql, min(left - 4, 15)) or []
                for e in ev:
                    m = netdiag.DHCP_RE.search(e.get("p") or "")
                    if m and m.group(1) == res["ip"]:
                        notes.append(f"📒 DHCP: остання видача {res['ip']} → {m.group(2)}"
                                     + (f" ({m.group(3)})" if m.group(3) else "")
                                     + f" о {time.strftime('%d.%m %H:%M', time.localtime(int(e['ts']) // 1000))}")
                        res = await asyncio.to_thread(netdiag.diagnose_fast, cfg, f"{res['ip']} {m.group(2)}")
                        break
                else:
                    notes.append(f"📒 DHCP: за {cfg.get('netdiag_dhcp_hours')} год видач цього IP немає — адреса статична або не з наших пулів.")
        mac = res.get("mac")
        if mac:
            left = deadline - time.monotonic()
            if left > 4:
                ev = await tracker.run_aql(client, api, headers, netdiag.nps_aql(mac, minutes), min(left - 2, 20))
                nps = None if ev is None else [netdiag.parse_nps(e) for e in ev]
    return netdiag.render_card(res, nps, notes, minutes)


HELP = ("Я діагностую підключення пристрою. Надішліть його *IP* (або MAC), напр. `172.17.104.25`.\n"
        "Покажу: Wi-Fi чи кабель; для Wi-Fi — точку, SSID, сигнал/SNR, стан на контролері і історію за 15 хв; "
        "для кабелю — свіч, порт, швидкість, помилки, 802.1X; і що каже NPS (чому не авторизувався).")


# ============================================================================ HTTP
@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/chat")
async def chat(request: Request):
    cfg = conf()
    peer = request.client.host if request.client else ""
    if peer not in set(cfg.get("netdiag_trusted_proxies")):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not await asyncio.to_thread(verify_chat_token, token.strip(), cfg.get("netdiag_chat_audience")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        event = await request.json()
    except Exception:
        return JSONResponse({"error": "bad request"}, status_code=400)
    if not isinstance(event, dict):
        return JSONResponse({"error": "bad request"}, status_code=400)

    etype = event.get("type")
    user = event.get("user") or {}
    email = (user.get("email") or "").strip().lower() if user.get("type") == "HUMAN" else ""
    if etype not in ("MESSAGE", "ADDED_TO_SPACE", "CARD_CLICKED"):
        return JSONResponse({})
    if not await asyncio.to_thread(authorized, cfg, email):
        log.info(f"deny user={email or '?'} event={etype}")
        if event.get("isDialogEvent"):
            return JSONResponse(ui.dialog_error("У вас немає доступу до діагностики мережі."))
        return JSONResponse({"text": "⛔ У вас немає доступу до діагностики мережі. Зверніться до NOC."})
    if etype == "CARD_CLICKED":
        try:
            return JSONResponse(await card_clicked(cfg, event, email))
        except Exception as e:
            log.exception(f"card click failed: {e}")
            if event.get("isDialogEvent"):
                return JSONResponse(ui.dialog_error("Внутрішня помилка — деталі в журналі бота."))
            return JSONResponse({"actionResponse": {"type": "NEW_MESSAGE"}, "text": "⚠️ Внутрішня помилка — деталі в журналі бота."})
    text = ((event.get("message") or {}).get("argumentText") or (event.get("message") or {}).get("text") or "")[:500]
    pa = await asyncio.to_thread(pa_allowed, cfg, email)
    if etype == "ADDED_TO_SPACE" or not text.strip() or text.strip().lower() in ("help", "/help", "допомога", "?", "меню", "menu", "/menu", "start", "/start"):
        log.info(f"home user={email} event={etype}")
        return JSONResponse(ui.home(email, pa))
    if not rate_ok(cfg, email):
        return JSONResponse({"text": "⏳ Забагато запитів — спробуйте за хвилину."})
    cmd = netdiag_pa.parse_command(text)
    if cmd:
        log.info(f"pa-ask user={email} op={cmd['op']} ip={cmd.get('ip')}")
        if not pa:
            return JSONResponse({"text": "⛔ Дії на Palo Alto вам не дозволені."})
        p, err = netdiag_pa.validate(cfg, cmd["op"], cmd.get("ip"), cmd.get("hours"))
        if not p:
            return JSONResponse({"text": f"⚠️ {err}\n\n{netdiag_pa.HELP_PA}"})
        return JSONResponse(await asyncio.to_thread(netdiag_pa.confirm_card, cfg, p))
    target = netdiag.parse_ip(text, cfg) or netdiag.parse_mac(text)
    log.info(f"query user={email} target={target or '-'}")
    if not target:
        return JSONResponse(ui.home(email, pa))
    return JSONResponse(await diag_body(cfg, text, pa))


async def diag_body(cfg: dict, text: str, pa: bool) -> dict:
    try:
        body = await run_query(cfg, text)
    except Exception as e:
        log.exception(f"diagnose failed: {e}")
        return {"text": "⚠️ Діагностика впала з помилкою — деталі в журналі netdiag_bot.log."}
    if "cardsV2" in body:
        body["cardsV2"][0]["card"]["sections"].append(
            ui.result_actions(netdiag.parse_ip(text, cfg) or netdiag.parse_mac(text), pa))
    return body


def pa_allowed(cfg: dict, email: str) -> bool:
    """Дії на PA — окрема група (типово та сама noc@); allowlist netdiag_allowed_users теж діє."""
    email = (email or "").strip().lower()
    if email in {u.strip().lower() for u in cfg.get("netdiag_allowed_users") or []}:
        return True
    group = (cfg.get("netdiag_pa_group") or netdiag_pa.DEFAULTS["netdiag_pa_group"]).strip().lower()
    return bool(EMAIL_RE.match(email)) and email.endswith("@" + cfg.get("netdiag_allowed_domain").lower()) \
        and in_group(cfg, email, group)


def _click_params(event: dict) -> tuple[str, dict]:
    common = event.get("common") or {}
    fn = common.get("invokedFunction") or (event.get("action") or {}).get("actionMethodName") or ""
    params = dict(common.get("parameters") or {})
    for kv in (event.get("action") or {}).get("parameters") or []:
        if isinstance(kv, dict) and "key" in kv:
            params.setdefault(kv["key"], kv.get("value"))
    return fn, {k: str(v)[:64] for k, v in params.items()}


async def card_clicked(cfg: dict, event: dict, email: str) -> dict:
    fn, prm = _click_params(event)
    aid = secrets.token_hex(3)  # ID дії: ключ треду + мітка в журналі
    if event.get("isDialogEvent") and event.get("dialogEventType") == "CANCEL_DIALOG":
        return ui.dialog_close()
    pa = await asyncio.to_thread(pa_allowed, cfg, email)
    new = {"actionResponse": {"type": "NEW_MESSAGE"}}

    # --- відкрити діалоги / меню
    if fn == "dlg_diag":
        return ui.dlg_diag(prm.get("ip", ""))
    if fn in ("dlg_inet", "dlg_unblock"):
        if not pa:
            return {**new, "text": "⛔ Дії на Palo Alto вам не дозволені."}
        ip = netdiag_pa.parse_ipv4(prm.get("ip", "")) or ""
        return ui.dlg_inet(ip) if fn == "dlg_inet" else ui.dlg_unblock(ip)
    if fn == "show_home":
        return {**new, **ui.home(email, pa)}

    # --- діагностика (діалог або кнопка «ще раз»)
    if fn in ("submit_diag", "run_diag"):
        raw = ui.form_value(event, "ip") if fn == "submit_diag" else prm.get("ip", "")
        target = netdiag.parse_ip(raw, cfg) or netdiag.parse_mac(raw)
        if not target:
            msg = "Потрібен внутрішній IP (172.17.x.x, 172.18.48-55.x, 192.168.48-55.x) або MAC."
            return ui.dialog_error(msg) if fn == "submit_diag" else {**new, "text": "⚠️ " + msg}
        if not rate_ok(cfg, email):
            return ui.dialog_error("Забагато запитів — спробуйте за хвилину.") if fn == "submit_diag" \
                else {**new, "text": "⏳ Забагато запитів — спробуйте за хвилину."}
        log.info(f"[#{aid}] diag start user={email} target={target} via={fn}")
        # Діалог/кнопку Chat чекає лише кілька секунд, а діагностика з NPS — 5–10 с: відповідаємо одразу,
        # результат доставляємо окремим повідомленням через Chat API.
        space = (event.get("space") or {}).get("name", "")
        # усе — в один тред: тред повідомлення з кнопкою (меню або картка в треді меню).
        # На телефоні купа окремих тредів незручна (відгук користувача 12.11).
        thread = ((event.get("message") or {}).get("thread") or {}).get("name", "")
        spawn(diag_async(cfg, raw, pa, space, thread, email, aid))
        note = f"🔎 Діагностую {target}… результат прийде окремим повідомленням за кілька секунд."
        if fn == "submit_diag":
            return {"actionResponse": {"type": "DIALOG", "dialogAction": {"actionStatus": {
                "statusCode": "OK", "userFacingMessage": note}}}}
        return {**new, "text": note}

    # --- дії на Palo Alto з діалогів
    if fn in ("submit_inet", "submit_unblock"):
        if not pa:
            return ui.dialog_error("Дії на Palo Alto вам не дозволені.")
        if not rate_ok(cfg, email):
            return ui.dialog_error("Забагато запитів — спробуйте за хвилину.")
        if fn == "submit_inet":
            hours = ui.form_value(event, "custom_hours") or ui.form_value(event, "hours")
            p, err = netdiag_pa.validate(cfg, "inet", ui.form_value(event, "ip"), hours)
        else:
            p, err = netdiag_pa.validate(cfg, "unblock", ui.form_value(event, "ip"))
        if not p:
            return ui.dialog_error(err)
        log.info(f"[#{aid}] pa start user={email} op={p['op']} ip={p['ip']}" + (f" hours={p['hours']}" if p.get("hours") else ""))
        ok, msg = await asyncio.to_thread(netdiag_pa.execute, cfg, p, email, aid)
        body = await asyncio.to_thread(netdiag_pa.result_card, cfg, p, ok, msg, email)
        body["cardsV2"][0]["card"]["sections"].append(ui.result_actions(p["ip"] if p["op"] == "inet" else None, pa))
        # усе — в один тред повідомлення з кнопкою (тред меню)
        space = (event.get("space") or {}).get("name", "")
        thread = ((event.get("message") or {}).get("thread") or {}).get("name", "")
        tag_action(body, aid)
        delivered = await asyncio.to_thread(chat_post, cfg, space, body, thread)
        log.info(f"[#{aid}] pa done ok={ok} delivered={delivered} thread={thread or '-'}")
        if delivered:
            return {"actionResponse": {"type": "DIALOG", "dialogAction": {"actionStatus": {
                "statusCode": "OK", "userFacingMessage": ("✅ " if ok else "⛔ ") + msg[:200]}}}}
        return {**new, **body}

    # --- текстові команди: картка підтвердження
    if fn not in ("pa_ask", "pa_confirm", "pa_cancel"):
        return {}
    if fn == "pa_cancel":
        log.info(f"pa-cancel user={email} ip={prm.get('ip')}")
        return {"actionResponse": {"type": "UPDATE_MESSAGE"}, "text": f"Скасовано ({netdiag._e(prm.get('ip'))})."}
    if not pa:
        return {**new, "text": "⛔ Дії на Palo Alto вам не дозволені."}
    if not rate_ok(cfg, email):
        return {**new, "text": "⏳ Забагато запитів — спробуйте за хвилину."}
    p, err = netdiag_pa.validate(cfg, prm.get("op", ""), prm.get("ip"), prm.get("hours"))
    if not p:
        return {**new, "text": f"⚠️ {err}"}
    if fn == "pa_ask":
        body = await asyncio.to_thread(netdiag_pa.confirm_card, cfg, p)
        return {**new, **body}
    try:
        age = time.time() - int(prm.get("t", "0"))
    except ValueError:
        age = 1e9
    if not 0 <= age <= 600:
        return {"actionResponse": {"type": "UPDATE_MESSAGE"}, "text": "⌛ Підтвердження застаріло (> 10 хв) — надішліть команду ще раз."}
    ok, msg = await asyncio.to_thread(netdiag_pa.execute, cfg, p, email)
    body = await asyncio.to_thread(netdiag_pa.result_card, cfg, p, ok, msg, email)
    return {"actionResponse": {"type": "UPDATE_MESSAGE"}, **body}
