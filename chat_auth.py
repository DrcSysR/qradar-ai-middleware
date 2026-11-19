"""Перевірка OIDC-токена, яким Google Chat підписує запити до HTTP-ендпоінта застосунку.

Той самий код, що й у netdiag_bot.py (там він вбудований і прив'язаний до netdiag-конфігу); тут винесений
у самостійний модуль без побічних ефектів при імпорті — його використовує cortex_bot.py. netdiag_bot.py
не чіпали (живий сервіс); при нагоді він може імпортувати цей модуль замість власної копії.

Токен: JWT RS256 від accounts.google.com, email = chat@system.gserviceaccount.com, aud = URL ендпоінта.
Сміття відсіюється ДО мережі (regex + kid із заголовка), сертифікати Google кешуються за Cache-Control —
інакше будь-який `Bearer <що завгодно>` змушував би бота качати сертифікати (DoS-підсилювач).
"""
from __future__ import annotations

import base64
import json
import logging
import re
import threading
import time

log = logging.getLogger("chat_auth")

CHAT_ISSUER = "chat@system.gserviceaccount.com"
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")
GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
JWT_RE = re.compile(r"^[A-Za-z0-9_-]{10,2000}\.[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,1000}$")
CERTS_MIN_REFRESH = 60

_lock = threading.Lock()
_certs: dict = {}
_certs_exp = 0.0
_certs_fetched = 0.0
_session = None


def _http():
    global _session
    if _session is None:
        import requests
        _session = requests.Session()
    return _session


def _jwt_kid(token: str):
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


def _google_certs(kid: str) -> dict:
    global _certs, _certs_exp, _certs_fetched
    with _lock:
        now = time.time()
        if kid in _certs and now < _certs_exp:
            return _certs
        if now - _certs_fetched < CERTS_MIN_REFRESH:
            return _certs
        _certs_fetched = now
        r = _http().get(GOOGLE_CERTS_URL, timeout=10)
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


# ============================================================================ членство в групі (Cloud Identity)
CI_API = "https://cloudidentity.googleapis.com/v1"
CI_SCOPE = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_ci_lock = threading.Lock()
_ci_sessions: dict = {}
_group_name: dict = {}
_member_cache: dict = {}
MEMBER_TTL = 120          # секунд: вилучення з групи діє не пізніше ніж за 2 хв


def _ci(key_file: str):
    with _ci_lock:
        if key_file not in _ci_sessions:
            from google.auth.transport.requests import AuthorizedSession
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_file(key_file, scopes=[CI_SCOPE])
            _ci_sessions[key_file] = AuthorizedSession(creds)
        return _ci_sessions[key_file]


def in_group(key_file: str, email: str, group: str) -> bool:
    """Транзитивне членство email у групі. Будь-яка помилка = НЕ член (fail closed)."""
    email, group = (email or "").strip().lower(), (group or "").strip().lower()
    if not (EMAIL_RE.match(email) and EMAIL_RE.match(group)):
        return False
    key = (group, email)
    now = time.monotonic()
    hit = _member_cache.get(key)
    if hit and hit[1] > now:
        return hit[0]
    try:
        s = _ci(key_file)
        if group not in _group_name:
            r = s.get(f"{CI_API}/groups:lookup", params={"groupKey.id": group}, timeout=10)
            r.raise_for_status()
            _group_name[group] = r.json()["name"]
        r = s.get(f"{CI_API}/{_group_name[group]}/memberships:checkTransitiveMembership",
                  params={"query": f"member_key_id == '{email}'"}, timeout=10)   # email провалідований regex
        r.raise_for_status()
        member = bool(r.json().get("hasMembership"))
    except Exception as e:
        log.error(f"group check failed ({group}): {type(e).__name__}")
        return False
    _member_cache[key] = (member, now + MEMBER_TTL)
    return member
