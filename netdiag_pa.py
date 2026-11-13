"""Palo Alto pa-vm для netdiag-бота: зняти `wan-block` з IP і дати внутрішньому IP `tmp-inet`
на N годин/днів — через User-ID XML API (`type=user-id`, uid-message register/unregister).

Тільки pa-vm (VM-300, 172.17.64.101): pa440 — інший сайт, теги туди не пушимо (рішення 07.08.2026).
Ключ — `netdiag_pa_uid_key` (BW «PaloAlto API Key», поле user-id ключа); передається в заголовку
X-PAN-KEY, НЕ в query string (інакше потрапляє в логи nginx/QRadar). TLS — повна перевірка
серта PA корпоративним CA MODERN-CA-G2 (`netdiag_pa_ca_file`), серт має IP SAN 172.17.64.101.

Читання поточних тегів (`show object registered-ip`) — op-запит, user-id ключу заборонений (403).
Якщо задано окремий op-ключ `netdiag_pa_op_key`, бот показує теги IP і залишок таймауту; інакше —
лише результат дії.

Правила (перевіряються тут, а не в UI — параметри кнопок приходять від клієнта):
  * unblock: публічний IPv4 (is_global), теги з `netdiag_pa_unblock_tags` (типово wan-block);
  * tmp-inet: IP з `netdiag_allowed_networks` (внутрішні), 1 год … `netdiag_pa_max_hours` (720 = 30 діб;
    максимум PAN-OS для timeout — 2592000 с).
Кожна дія пишеться в таблицю `pa_actions` netdiag.db (хто, що, коли, результат) і в журнал бота.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import ssl
import threading
import time
import xml.etree.ElementTree as ET

import httpx

import netdiag

log = logging.getLogger("netdiag_pa")

DEFAULTS = {
    "netdiag_pa_host": "172.17.64.101",
    "netdiag_pa_ca_file": "/opt/qradar-middleware/netdiag_tls/modern-ca-g2.pem",
    "netdiag_pa_inet_tag": "tmp-inet",
    "netdiag_pa_unblock_tags": ["wan-block"],
    "netdiag_pa_max_hours": 720,
    "netdiag_pa_group": "noc@modern-expo.com",
}
PANOS_MAX_TIMEOUT = 2592000

AUDIT_SQL = """CREATE TABLE IF NOT EXISTS pa_actions (
  ts INTEGER, user TEXT, action TEXT, ip TEXT, tag TEXT, timeout_s INTEGER, ok INTEGER, detail TEXT)"""


def pcfg(cfg: dict, key: str):
    v = cfg.get(key)
    return DEFAULTS[key] if v in (None, "", []) else v


# ============================================================================ розбір команд
DUR_RE = re.compile(r"(\d{1,4})\s*(г|год|годин[аи]?|h|hr|hours?|д|дн|днів|дня|день|d|days?)?\b", re.I)
UNBLOCK_RE = re.compile(r"^\s*(розблок\w*|unblock|зняти\s+wan-?block|wan-?block\s+зняти|untag)\b", re.I)
INET_RE = re.compile(r"^\s*(інтернет|інет|inet|tmp-?inet)\b", re.I)


def parse_ipv4(text: str) -> str | None:
    m = re.search(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", text or "")
    if not m:
        return None
    try:
        return str(ipaddress.IPv4Address(m.group(1)))
    except ValueError:
        return None


def parse_hours(text: str) -> int | None:
    """'4', '4г', '8 год', '2д', '3 days' → години. Без одиниці — години."""
    rest = re.sub(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", " ", text or "")
    m = DUR_RE.search(rest)
    if not m:
        return None
    n = int(m.group(1))
    unit = (m.group(2) or "").lower()
    return n * 24 if unit[:1] in ("д", "d") else n


def parse_command(text: str) -> dict | None:
    """Команди PA з тексту повідомлення. None — це не команда PA (тоді звичайна діагностика)."""
    if UNBLOCK_RE.match(text or ""):
        return {"op": "unblock", "ip": parse_ipv4(text)}
    if INET_RE.match(text or ""):
        return {"op": "inet", "ip": parse_ipv4(text), "hours": parse_hours(text)}
    return None


def validate(cfg: dict, op: str, ip: str | None, hours=None) -> tuple[dict | None, str]:
    """Перевірка параметрів дії (з тексту АБО з кнопки — однаково недовірені). (params, помилка)."""
    try:
        addr = ipaddress.IPv4Address(str(ip or ""))
    except ValueError:
        return None, "Не бачу коректного IPv4."
    if op == "unblock":
        if not addr.is_global:
            return None, f"{addr} — не публічна адреса; wan-block ставиться на зовнішні IP."
        return {"op": "unblock", "ip": str(addr)}, ""
    if op == "inet":
        nets = [ipaddress.ip_network(n, strict=False) for n in netdiag.opt(cfg, "netdiag_allowed_networks")]
        if not any(addr in n for n in nets):
            return None, f"{addr} — не внутрішня адреса наших мереж; tmp-inet дається лише внутрішнім IP."
        try:
            h = int(hours)
        except (TypeError, ValueError):
            return None, "Вкажіть строк: годин (`4г`, `8 год`) або днів (`2д`). Напр. `інтернет 172.17.40.25 4г`."
        mx = min(int(pcfg(cfg, "netdiag_pa_max_hours")), PANOS_MAX_TIMEOUT // 3600)
        if not 1 <= h <= mx:
            return None, f"Строк має бути від 1 год до {mx} год ({mx // 24} діб)."
        return {"op": "inet", "ip": str(addr), "hours": h}, ""
    return None, "Невідома дія."


def human_hours(h: int) -> str:
    if h % 24 == 0:
        d = h // 24
        return f"{d} " + ("день" if d == 1 else "дні" if d in (2, 3, 4) else "днів")
    return f"{h} год"


# ============================================================================ PAN-OS API
def _client(cfg: dict) -> httpx.Client:
    ctx = ssl.create_default_context(cafile=pcfg(cfg, "netdiag_pa_ca_file"))
    return httpx.Client(verify=ctx, timeout=20)


def _uid_message(kind: str, ip: str, tag: str, timeout_s: int | None) -> str:
    member = f'<member timeout="{int(timeout_s)}">{tag}</member>' if timeout_s else f"<member>{tag}</member>"
    persistent = ' persistent="1"' if kind == "register" else ""
    return (f"<uid-message><version>2.0</version><type>update</type><payload><{kind}>"
            f'<entry ip="{ip}"{persistent}><tag>{member}</tag></entry>'
            f"</{kind}></payload></uid-message>")


def _resp(text: str) -> tuple[bool, str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return False, "неочікувана відповідь PA"
    ok = root.get("status") == "success"
    msg = " ".join(t.strip() for t in root.itertext() if t.strip())[:300]
    return ok, msg


def uid_call(cfg: dict, kind: str, ip: str, tag: str, timeout_s: int | None) -> tuple[bool, str]:
    key = cfg.get("netdiag_pa_uid_key") or ""
    if not key:
        return False, "не налаштовано ключ PA (netdiag_pa_uid_key)"
    # ip і tag вже провалідовані (IPv4Address / тег з конфіга) — XML-ін'єкція неможлива
    cmd = _uid_message(kind, ip, tag, timeout_s)
    try:
        with _client(cfg) as c:
            r = c.post(f"https://{pcfg(cfg, 'netdiag_pa_host')}/api/", headers={"X-PAN-KEY": key},
                       data={"type": "user-id", "cmd": cmd})
    except Exception as e:
        return False, f"PA недоступний: {type(e).__name__}"
    if r.status_code != 200:
        return False, f"PA HTTP {r.status_code}" + (" — ключ відхилено" if r.status_code == 403 else "")
    return _resp(r.text)


def registered_tags(cfg: dict, ip: str) -> dict[str, int | None] | None:
    """{тег: секунд до спливання | None (без таймауту)} або None, якщо op-ключа немає/помилка."""
    key = cfg.get("netdiag_pa_op_key") or ""
    if not key:
        return None
    cmd = f"<show><object><registered-ip><ip>{ip}</ip></registered-ip></object></show>"
    try:
        with _client(cfg) as c:
            r = c.post(f"https://{pcfg(cfg, 'netdiag_pa_host')}/api/", headers={"X-PAN-KEY": key},
                       data={"type": "op", "cmd": cmd})
        root = ET.fromstring(r.text)
    except Exception as e:
        log.warning(f"PA registered-ip {ip}: {type(e).__name__}")
        return None
    if root.get("status") != "success":
        return None
    tags: dict[str, int | None] = {}
    for entry in root.iter("entry"):
        if entry.get("ip") != ip:
            continue
        for m in entry.iter("member"):
            t = (m.text or "").strip()
            if t:
                to = m.get("timeout") or m.get("expire")
                tags[t] = int(to) if to and to.isdigit() else None
    return tags


# ============================================================================ дії + аудит
def audit(cfg: dict, user: str, action: str, ip: str, tag: str, timeout_s: int | None, ok: bool, detail: str,
          aid: str = "") -> None:
    try:
        con = netdiag.db(cfg)
        con.execute(AUDIT_SQL)
        con.execute("INSERT INTO pa_actions VALUES(?,?,?,?,?,?,?,?)",
                    (int(time.time()), user, action, ip, tag, timeout_s, int(ok), (f"#{aid} " if aid else "") + detail[:290]))
        con.commit()
        con.close()
    except Exception as e:
        log.error(f"audit pa_actions: {e}")
    log.info(f"[#{aid}] PA {action} ip={ip} tag={tag} timeout={timeout_s} user={user} ok={ok} {detail[:120]}")


def _execute(cfg: dict, p: dict, user: str, aid: str) -> tuple[bool, str]:
    if p["op"] == "unblock":
        results = []
        all_ok = True
        for tag in pcfg(cfg, "netdiag_pa_unblock_tags"):
            ok, msg = uid_call(cfg, "unregister", p["ip"], tag, None)
            if not ok:
                # як у формі helpdesk: перереєстрація з timeout=1 — тег спливе за секунду
                ok2, msg2 = uid_call(cfg, "register", p["ip"], tag, 1)
                ok, msg = ok2, (msg2 if ok2 else f"{msg}; {msg2}")
            audit(cfg, user, "unblock", p["ip"], tag, None, ok, msg, aid)
            all_ok &= ok
            results.append(f"{tag}: {'знято' if ok else 'помилка — ' + msg}")
        return all_ok, "; ".join(results)
    tag = pcfg(cfg, "netdiag_pa_inet_tag")
    secs = p["hours"] * 3600
    ok, msg = uid_call(cfg, "register", p["ip"], tag, secs)
    audit(cfg, user, "inet", p["ip"], tag, secs, ok, msg, aid)
    return ok, (f"{tag} на {human_hours(p['hours'])}" if ok else f"помилка — {msg}")


def execute(cfg: dict, p: dict, user: str, aid: str = "") -> tuple[bool, str]:
    ok, text = _execute(cfg, p, user, aid)
    notify(cfg, user, p, ok, text, aid)
    return ok, text


# ============================================================================ сповіщення
# Кожна зміна на PA з бота дублюється в окремий простір Chat (вебхук `netdiag_pa_notify_webhook`, секрет у
# config.json): якщо акаунт із noc@ зламано і ним знімають wan-block / відкривають інтернет — це видно одразу,
# а не лише в pa_actions. Порожній ключ = вимкнено.
WEBHOOK_RE = re.compile(r"^https://chat\.googleapis\.com/v1/spaces/[A-Za-z0-9_-]+/messages\?[A-Za-z0-9_=&%.-]+$")


def _notify_text(user: str, p: dict, ok: bool, text: str, aid: str) -> str:
    what = "зняття wan-block" if p["op"] == "unblock" else "tmp-inet"
    mark = "✅" if ok else "⚠️ НЕВДАЛО"
    return (f"🔐 *netdiag → pa-vm*: {what} {mark}\n"
            f"IP: `{p['ip']}` · хто: {user or '?'} · дія #{aid or '-'}\n{text[:300]}")


def notify(cfg: dict, user: str, p: dict, ok: bool, text: str, aid: str = "") -> None:
    url = (cfg.get("netdiag_pa_notify_webhook") or "").strip()
    if not url:
        return
    if not WEBHOOK_RE.match(url):
        log.error("netdiag_pa_notify_webhook: не схоже на вебхук Google Chat — сповіщення не надіслано")
        return
    body = {"text": _notify_text(user, p, ok, text, aid)}

    def _send():
        try:
            r = httpx.post(url, json=body, timeout=10)
            if r.status_code != 200:
                log.warning(f"[#{aid}] PA notify HTTP {r.status_code}")
        except Exception as e:  # URL (з ключем) у журнал не пишемо
            log.warning(f"[#{aid}] PA notify failed: {type(e).__name__}")

    threading.Thread(target=_send, daemon=True).start()


# ============================================================================ картки
def _btn(text: str, fn: str, params: dict, color: str | None = None) -> dict:
    b = {"text": text, "onClick": {"action": {"function": fn,
                                              "parameters": [{"key": k, "value": str(v)} for k, v in params.items()]}}}
    if color:
        r, g, bl = (int(color[i:i + 2], 16) / 255 for i in (1, 3, 5))
        b["color"] = {"red": r, "green": g, "blue": bl, "alpha": 1}
    return b


def _tags_text(tags: dict | None) -> str:
    if tags is None:
        return "поточні теги не читаються (немає op-ключа)"
    if not tags:
        return "тегів немає"
    return ", ".join(f"{netdiag._e(t)}" + (f" (ще {netdiag.fmt_ago(s)})" if s else "") for t, s in tags.items())


def confirm_card(cfg: dict, p: dict) -> dict:
    tags = registered_tags(cfg, p["ip"])
    now = int(time.time())
    if p["op"] == "unblock":
        title, what = "Зняти блокування", f"Зняти <b>{', '.join(pcfg(cfg, 'netdiag_pa_unblock_tags'))}</b> з <b>{p['ip']}</b>"
        params = {"op": "unblock", "ip": p["ip"], "t": now}
    else:
        tag = pcfg(cfg, "netdiag_pa_inet_tag")
        title, what = "Тимчасовий інтернет", f"Дати <b>{p['ip']}</b> тег <b>{tag}</b> на <b>{human_hours(p['hours'])}</b>"
        params = {"op": "inet", "ip": p["ip"], "hours": p["hours"], "t": now}
    sections = [{"widgets": [
        {"decoratedText": {"topLabel": "Дія на pa-vm", "text": what, "wrapText": True,
                           "startIcon": {"materialIcon": {"name": "security"}}}},
        {"decoratedText": {"topLabel": "Зараз на IP", "text": _tags_text(tags), "wrapText": True,
                           "startIcon": {"materialIcon": {"name": "sell"}}}},
        {"buttonList": {"buttons": [_btn("Підтвердити", "pa_confirm", params, netdiag.RED if p["op"] == "unblock" else netdiag.GREEN),
                                    _btn("Скасувати", "pa_cancel", {"ip": p["ip"]})]}},
    ]}]
    return {"fallbackText": f"{title}: {p['ip']}",
            "cardsV2": [{"cardId": "pa_confirm", "card": {"header": {"title": title, "subtitle": "Palo Alto pa-vm · потрібне підтвердження"},
                                                          "sections": sections}}]}


def result_card(cfg: dict, p: dict, ok: bool, msg: str, user: str) -> dict:
    color = netdiag.GREEN if ok else netdiag.RED
    tags = registered_tags(cfg, p["ip"]) if ok else None
    widgets = [{"decoratedText": {"topLabel": "Результат", "wrapText": True,
                                  "text": netdiag._c(("✅ " if ok else "⛔ ") + netdiag._e(msg), color),
                                  "startIcon": {"materialIcon": {"name": "check_circle" if ok else "error"}}}},
               {"decoratedText": {"topLabel": "Хто", "text": netdiag._e(user), "startIcon": {"materialIcon": {"name": "person"}}}}]
    if tags is not None:
        widgets.append({"decoratedText": {"topLabel": "Теги IP зараз", "text": _tags_text(tags), "wrapText": True,
                                          "startIcon": {"materialIcon": {"name": "sell"}}}})
    return {"cardsV2": [{"cardId": "pa_result", "card": {
        "header": {"title": f"{'Блокування знято' if p['op'] == 'unblock' else 'Тимчасовий інтернет'}: {p['ip']}",
                   "subtitle": "Palo Alto pa-vm"},
        "sections": [{"widgets": widgets}]}}]}


HELP_PA = ("*Palo Alto (pa-vm):*\n"
           "• `розблокуй 1.2.3.4` — зняти wan-block із зовнішнього IP\n"
           "• `інтернет 172.17.40.25 4г` (або `8 год`, `2д`) — тег tmp-inet внутрішньому IP на строк\n"
           "Кожна дія — після кнопки «Підтвердити», журналюється (хто/що/коли).")
