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
import threading
import time
from logging.handlers import RotatingFileHandler

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import netdiag
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


def verify_chat_token(token: str, audience: str) -> bool:
    from google.oauth2 import id_token
    try:
        claims = id_token.verify_oauth2_token(token, _google_request(), audience=audience, clock_skew_in_seconds=30)
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


async def run_query(cfg: dict, text: str) -> str:
    deadline = time.monotonic() + float(cfg.get("netdiag_reply_budget_seconds"))
    res = await asyncio.to_thread(netdiag.diagnose_fast, cfg, text)
    if res.get("error") == "no_target":
        return netdiag.render_fast(res)
    api, headers = _qradar(cfg)
    extra = []
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
                        extra.append(f"📒 DHCP: остання видача {res['ip']} → `{m.group(2)}`"
                                     + (f" ({m.group(3)})" if m.group(3) else "")
                                     + f" о {time.strftime('%d.%m %H:%M', time.localtime(int(e['ts']) // 1000))}")
                        res = await asyncio.to_thread(netdiag.diagnose_fast, cfg, f"{res['ip']} {m.group(2)}")
                        break
                else:
                    extra.append(f"📒 DHCP: за {cfg.get('netdiag_dhcp_hours')} год видач цього IP немає — адреса статична або не з наших пулів.")
        body = netdiag.render_fast(res)
        mac = res.get("mac")
        if mac:
            left = deadline - time.monotonic()
            minutes = int(cfg.get("netdiag_nps_minutes") or 60)
            if left > 4:
                ev = await tracker.run_aql(client, api, headers, netdiag.nps_aql(mac, minutes), min(left - 2, 20))
                if ev is None:
                    extra.append("🔐 NPS: QRadar не відповів вчасно — авторизацію не перевірено.")
                else:
                    extra.append(netdiag.render_nps([netdiag.parse_nps(e) for e in ev], minutes))
            else:
                extra.append("🔐 NPS: не встиг перевірити (ліміт часу відповіді).")
    return "\n".join([body, *extra])


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
    if etype not in ("MESSAGE", "ADDED_TO_SPACE"):
        return JSONResponse({})
    text = ((event.get("message") or {}).get("argumentText") or (event.get("message") or {}).get("text") or "")[:500]
    if not await asyncio.to_thread(authorized, cfg, email):
        log.info(f"deny user={email or '?'}")
        return JSONResponse({"text": "⛔ У вас немає доступу до діагностики мережі. Зверніться до NOC."})
    if etype == "ADDED_TO_SPACE" or not text.strip() or text.strip().lower() in ("help", "/help", "допомога", "?"):
        return JSONResponse({"text": HELP})
    if not rate_ok(cfg, email):
        return JSONResponse({"text": "⏳ Забагато запитів — спробуйте за хвилину."})
    target = netdiag.parse_ip(text, cfg) or netdiag.parse_mac(text)
    log.info(f"query user={email} target={target or '-'}")
    if not target:
        return JSONResponse({"text": "Не бачу у повідомленні внутрішнього IP або MAC.\n" + HELP})
    try:
        reply = await run_query(cfg, text)
    except Exception as e:
        log.exception(f"diagnose failed target={target}: {e}")
        reply = "⚠️ Діагностика впала з помилкою — деталі в журналі netdiag_bot.log."
    return JSONResponse({"text": reply[:3900]})
