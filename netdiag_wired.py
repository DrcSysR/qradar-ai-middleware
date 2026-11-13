"""Розширена аналітика КАБЕЛЬНОГО підключення (кнопка під карткою «кабель»).

Типові скарги: «недостатня швидкість», «значок „немає інтернету“», «періодичні перепідключення».
Точка підключення (свіч + порт) уже відома з діагностики (`netdiag.wired_trace`); далі за останні
`netdiag_ai_minutes` хвилин:

  LibreNMS (`netdiag_librenms_url` / `_token`): журнал подій ЦЬОГО порту (ifOperStatus up/down, ifSpeed, ifDuplex,
      ifVlan — напр. 500 → 100 = 802.1X пустив не одразу), syslog свіча з рядками про цей порт (link up/down,
      «Blocked by AAA/STP»), стан порту за останнє опитування (дельти помилок/відкидань, трафік), свіч загалом:
      скільки ІНШИХ портів падали, STP/петлі/живлення в syslog, аптайм (перезавантаження), локація;
  живий SNMP: стан, швидкість, лічильники, PVID, 802.1X PAE; MAU-MIB — що РЕКЛАМУЄ мережева карта
      (ifMauAutoNegCapReceivedBits) проти швидкості лінку → «карта вміє 1 Гбіт/с, а лінк 100 Мбіт/с» = кабель/пара;
  NetBox (`netdiag_netbox_url` / `_token`): де стоїть свіч (сайт/локація/шафа) і що задокументовано на кабелі порту;
  QRadar DHCP / NPS / Palo Alto — спільний код із Wi-Fi (`netdiag_ai`).

Усі зовнішні виклики — лише читання; токени — з config.json (у журнал не пишуться).
"""
from __future__ import annotations

import logging
import re
import time
import urllib.parse

import httpx

import netdiag
import snmp_v2c as snmp

log = logging.getLogger("netdiag_wired")

DEFAULTS = {
    "netdiag_librenms_url": "http://172.17.61.230",
    "netdiag_librenms_token": "",
    "netdiag_netbox_url": "https://netbox.modern-expo.com",
    "netdiag_netbox_token": "",
}

O_MAU_REMSIG = "1.3.6.1.2.1.26.5.1.1.2"       # ifMauAutoNegRemoteSignaling: 1 detected, 2 notdetected
O_MAU_ADV = "1.3.6.1.2.1.26.5.1.1.10"         # ifMauAutoNegCapAdvertisedBits (свіч)
O_MAU_RECV = "1.3.6.1.2.1.26.5.1.1.11"        # ifMauAutoNegCapReceivedBits (мережева карта)
O_DOT3_DUPLEX = "1.3.6.1.2.1.10.7.2.1.19"     # dot3StatsDuplexStatus: 1 unknown, 2 half, 3 full
O_DOT3_FCS = "1.3.6.1.2.1.10.7.2.1.3"         # dot3StatsFCSErrors
O_DOT3_LATE = "1.3.6.1.2.1.10.7.2.1.8"        # dot3StatsLateCollisions (ознака duplex mismatch)
# IANA-MAU-MIB IANAifMauAutoNegCapBits → швидкість, Мбіт/с (BITS: біт 0 = старший біт першого байта)
MAU_BITS = {1: 10, 2: 10, 3: 100, 4: 100, 5: 100, 6: 100, 7: 100, 12: 1000, 13: 1000, 14: 1000, 15: 1000}


def opt(cfg: dict, key: str):
    v = cfg.get(key)
    return DEFAULTS.get(key) if v in (None, "") else v


def _clean_token(t: str) -> str:
    t = (t or "").strip()
    for p in ("token ", "bearer "):
        if t.lower().startswith(p):
            t = t[len(p):].strip()
    return t


# ============================================================================ SNMP: MAU / EtherLike
def _bits(v) -> list[int]:
    raw = v if isinstance(v, (bytes, bytearray)) else (v.encode("latin-1") if isinstance(v, str) else b"")
    return [i * 8 + j for i, byte in enumerate(raw) for j in range(8) if byte & (0x80 >> j)]


def mau_info(cfg: dict, sw_ip: str, ifindex: int, link_mbps: int | None = None) -> dict:
    """Що рекламує мережева карта (partner) і свіч; дуплекс, FCS, late collisions. {} якщо свіч не віддає."""
    info = (netdiag.switches(cfg) or {}).get(sw_ip) or {}
    if not info.get("community"):
        return {}
    s = snmp.Session(sw_ip, info["community"], timeout=2, retries=1)
    out: dict = {}
    try:
        r = s.get(f"{O_DOT3_DUPLEX}.{ifindex}", f"{O_DOT3_FCS}.{ifindex}", f"{O_DOT3_LATE}.{ifindex}")
        dup = r.get(f"{O_DOT3_DUPLEX}.{ifindex}")
        out["duplex"] = {1: "unknown", 2: "half", 3: "full"}.get(dup) if isinstance(dup, int) else None
        out["fcs"] = r.get(f"{O_DOT3_FCS}.{ifindex}") if isinstance(r.get(f"{O_DOT3_FCS}.{ifindex}"), int) else None
        out["late_coll"] = r.get(f"{O_DOT3_LATE}.{ifindex}") if isinstance(r.get(f"{O_DOT3_LATE}.{ifindex}"), int) else None
    except snmp.SnmpError:
        pass
    try:
        idx = f"{ifindex}.1"
        r = s.get(f"{O_MAU_REMSIG}.{idx}", f"{O_MAU_ADV}.{idx}", f"{O_MAU_RECV}.{idx}")
        rs = r.get(f"{O_MAU_REMSIG}.{idx}")
        recv = [b for b in _bits(r.get(f"{O_MAU_RECV}.{idx}")) if b in MAU_BITS]
        adv = [b for b in _bits(r.get(f"{O_MAU_ADV}.{idx}")) if b in MAU_BITS]
        if isinstance(rs, int):
            out["autoneg_partner"] = {1: "detected", 2: "notdetected"}.get(rs)
        if recv:
            nic = max(MAU_BITS[b] for b in recv)
            # Частина свічів (HP 2540 13.11) не кладе в ReceivedBits гігабітні можливості (вони йдуть «next pages»):
            # бітмап «до 100» при лінку 1000 — неповний, а не правда. Довіряємо лише бітмапу, що не менший за лінк.
            if not (isinstance(link_mbps, int) and link_mbps > 0 and nic < link_mbps):
                out["nic_max_mbps"] = nic
                out["nic_half_only"] = not any(b in recv for b in (2, 5, 7, 13, 15))
        if adv:
            out["switch_max_mbps"] = max(MAU_BITS[b] for b in adv)
    except snmp.SnmpError:
        pass
    return out


# ============================================================================ LibreNMS
def _lnms(cfg: dict, path: str, **q):
    tok = _clean_token(opt(cfg, "netdiag_librenms_token"))
    if not tok:
        return None
    url = opt(cfg, "netdiag_librenms_url").rstrip("/") + "/api/v0" + path
    try:
        r = httpx.get(url, params=q or None, headers={"X-Auth-Token": tok}, timeout=30)
    except httpx.HTTPError as e:
        log.warning(f"LibreNMS {path.split('/')[1]}: {type(e).__name__}")
        return None
    if r.status_code == 404:
        return {}
    if r.status_code >= 300:
        log.warning(f"LibreNMS {path.split('/')[1]}: HTTP {r.status_code}")
        return None
    return r.json()


def _port_tokens(ifname: str, bport: int | None, ifindex: int | None) -> list[re.Pattern]:
    """Як свічі різних виробників пишуть цей порт у syslog."""
    pats = []
    if ifname:
        pats.append(re.compile(rf"(?<![\w/]){re.escape(ifname)}(?![\w/])", re.I))
        m = re.search(r"(\d+(?:/\d+)*)$", ifname)
        if m:   # GigabitEthernet1/0/5 → «GE1/0/5», «1/0/5»; ProCurve «5»
            num = m.group(1)
            if "/" in num:
                pats.append(re.compile(rf"(?<![\w/.]){re.escape(num)}(?![\w/])"))
            else:
                pats.append(re.compile(rf"\b(?:port|interface|int)\s+{re.escape(num)}\b", re.I))
    if bport and not ifname.isdigit():
        pats.append(re.compile(rf"\bport\s+{bport}\b", re.I))
    return pats


SW_NOTABLE = [
    (re.compile(r"(?i)topology change|TCN|root (?:changed|bridge)|STP.*(?:block|chang)"), "STP"),
    (re.compile(r"(?i)loop|mac.?(?:flap|move)|storm"), "петля/шторм"),
    (re.compile(r"(?i)\bpoe\b|power.*(?:deny|fail|overload)|PSE"), "PoE/живлення"),
    (re.compile(r"(?i)fan|temperatur|power supply|PSU"), "залізо (вентилятор/температура/БЖ)"),
    (re.compile(r"(?i)cold ?start|warm ?start|reboot|restart(?:ed)?|system (?:is )?(?:up|start)"), "перезавантаження"),
]


def librenms_facts(cfg: dict, sw_ip: str, ifname: str, bport: int | None, ifindex: int | None, minutes: int) -> dict | None:
    """None — LibreNMS недоступний/не налаштований; {} — свіча там немає."""
    dev = _lnms(cfg, f"/devices/{urllib.parse.quote(sw_ip)}")
    if dev is None:
        return None
    d = (dev.get("devices") or [{}])[0] if dev else {}
    if not d:
        return {}
    f: dict = {"device": {"sysName": d.get("sysName"), "hardware": d.get("hardware"), "os": d.get("os"),
                          "location": d.get("location"), "uptime_s": d.get("uptime"), "status": d.get("status")}}
    # порт: за ifName, при промаху — за ifIndex зі списку портів
    p = _lnms(cfg, f"/devices/{urllib.parse.quote(sw_ip)}/ports/{urllib.parse.quote(ifname, safe='')}") if ifname else {}
    port = (p or {}).get("port") or None
    if isinstance(port, list):          # різні версії API: об'єкт або список з одного елемента
        port = port[0] if port else None
    if not port and ifindex:
        lst = _lnms(cfg, f"/devices/{urllib.parse.quote(sw_ip)}/ports", columns="port_id,ifName,ifIndex") or {}
        pid = next((x["port_id"] for x in lst.get("ports", []) if str(x.get("ifIndex")) == str(ifindex)), None)
        port = (_lnms(cfg, f"/ports/{pid}") or {}).get("port") if pid else None
        if isinstance(port, list):
            port = port[0] if port else None
    if port:
        speed = port.get("ifSpeed") or 0
        period = port.get("poll_period") or 300
        rate_in, rate_out = port.get("ifInOctets_rate") or 0, port.get("ifOutOctets_rate") or 0
        f["port"] = {"port_id": port.get("port_id"), "ifName": port.get("ifName"), "ifAlias": port.get("ifAlias"),
                     "oper": port.get("ifOperStatus"), "speed_mbps": round(speed / 1e6) if speed else None,
                     "duplex": port.get("ifDuplex"), "vlan": port.get("ifVlan"),
                     "in_err": port.get("ifInErrors_delta"), "out_err": port.get("ifOutErrors_delta"),
                     "in_disc": port.get("ifInDiscards_delta"), "out_disc": port.get("ifOutDiscards_delta"),
                     "in_mbps": round(rate_in * 8 / 1e6, 2), "out_mbps": round(rate_out * 8 / 1e6, 2),
                     "util_pct": round(100 * max(rate_in, rate_out) * 8 / speed) if speed else None,
                     "poll_age_s": int(time.time()) - int(port.get("poll_time") or 0) if port.get("poll_time") else None,
                     "poll_period_s": period}
    fr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - minutes * 60))
    ev = (_lnms(cfg, f"/logs/eventlog/{urllib.parse.quote(sw_ip)}", limit=1000, sortorder="DESC", **{"from": fr}) or {}).get("logs", [])
    pid = str((f.get("port") or {}).get("port_id") or "")
    mine = [e for e in ev if e.get("type") == "interface" and pid and str(e.get("reference")) == pid]
    other = [e for e in ev if e.get("type") == "interface" and str(e.get("reference")) != pid]
    def kinds(lst):
        c: dict[str, int] = {}
        for e in lst:
            k = (e.get("message") or "").split(":", 1)[0]
            c[k] = c.get(k, 0) + 1
        return c
    f["events"] = [{"t": e.get("datetime", "")[11:16], "m": (e.get("message") or "")[:80]} for e in reversed(mine)][-25:]
    f["event_kinds"] = kinds(mine)
    f["port_down"] = sum(1 for e in mine if "ifOperStatus" in (e.get("message") or "") and "-> down" in (e.get("message") or ""))
    f["other_ports_flapped"] = len({e.get("reference") for e in other
                                    if "ifOperStatus" in (e.get("message") or "") and "-> down" in (e.get("message") or "")})
    sl = (_lnms(cfg, f"/logs/syslog/{urllib.parse.quote(sw_ip)}", limit=1000, sortorder="DESC", **{"from": fr}) or {}).get("logs", [])
    pats = _port_tokens(ifname or "", bport, ifindex)
    f["syslog_port"] = [{"t": (s.get("timestamp") or "")[11:16], "m": re.sub(r"\s+", " ", s.get("msg") or "")[:120]}
                        for s in reversed(sl) if any(p.search(s.get("msg") or "") for p in pats)][-20:]
    notable: dict[str, int] = {}
    for s in sl:
        for rx, label in SW_NOTABLE:
            if rx.search(s.get("msg") or ""):
                notable[label] = notable.get(label, 0) + 1
                break
    f["syslog_switch"] = notable
    f["syslog_total"] = len(sl)
    return f


# ============================================================================ NetBox
def netbox_facts(cfg: dict, sw_ip: str, ifname: str) -> dict | None:
    tok = _clean_token(opt(cfg, "netdiag_netbox_token"))
    if not tok:
        return None
    base = opt(cfg, "netdiag_netbox_url").rstrip("/") + "/api"
    h = {"Authorization": f"Token {tok}", "Accept": "application/json"}
    try:
        with httpx.Client(timeout=30, verify=False, headers=h) as c:   # серт nginx2 — публічний LE, але ходимо по LAN
            ips = c.get(f"{base}/ipam/ip-addresses/", params={"address": sw_ip, "limit": 5}).json().get("results", [])
            dev = next(((r.get("assigned_object") or {}).get("device") for r in ips if (r.get("assigned_object") or {}).get("device")), None)
            if not dev:
                return {}
            d = c.get(f"{base}/dcim/devices/{dev['id']}/").json()
            f = {"device": d.get("name"), "site": (d.get("site") or {}).get("name"), "location": (d.get("location") or {}).get("display"),
                 "rack": (d.get("rack") or {}).get("name")}
            if ifname:
                its = c.get(f"{base}/dcim/interfaces/", params={"device_id": dev["id"], "name": ifname}).json().get("results", [])
                if its and its[0].get("cable"):
                    peers = its[0].get("link_peers") or []
                    f["cable_to"] = ", ".join(f"{p.get('display')}@{(p.get('device') or {}).get('display')}" for p in peers)[:120]
            return f
    except (httpx.HTTPError, ValueError) as e:
        log.warning(f"NetBox: {type(e).__name__}")
        return None


# ============================================================================ ознаки + текст
def hints(edge: dict, mau: dict, ln: dict | None) -> list[str]:
    out = []
    p = (ln or {}).get("port") or {}
    speed = edge.get("speed") or p.get("speed_mbps")
    if edge.get("oper") == "down" or p.get("oper") == "down":
        out.append("🔌 Порт зараз DOWN — кабель/розетка/мережева карта або пристрій вимкнено.")
    if (ln or {}).get("port_down", 0) >= 2:
        out.append(f"⚠️ Лінк падав {ln['port_down']} разів за вікно — кабель/розетка/патч-корд, енергозбереження карти "
                   "(EEE/Green Ethernet) або сон ПК.")
    spd_changes = (ln or {}).get("event_kinds", {}).get("ifSpeed", 0)
    if spd_changes >= 2:
        out.append(f"⚠️ Швидкість лінку змінювалась {spd_changes} разів — типово для пошкодженої пари/розетки.")
    if mau.get("nic_max_mbps") and speed and isinstance(speed, int) and mau["nic_max_mbps"] > speed:
        out.append(f"🐢 Мережева карта вміє {mau['nic_max_mbps']} Мбіт/с, а лінк піднявся на {speed} Мбіт/с — "
                   "у кабелі/розетці/патч-корді працюють не всі пари.")
    elif isinstance(speed, int) and 0 < speed < 1000 and not mau.get("nic_max_mbps"):
        out.append(f"🐢 Лінк {speed} Мбіт/с. Можливості карти свіч не віддає — якщо карта гігабітна, це кабель/пара.")
    if mau.get("autoneg_partner") == "notdetected":
        out.append("⚠️ Свіч не бачить автоузгодження від карти — швидкість/дуплекс задані вручну з одного боку (ризик duplex mismatch).")
    dup = mau.get("duplex") or {"halfDuplex": "half", "fullDuplex": "full"}.get(p.get("duplex") or "", None)
    if dup == "half":
        out.append("⛔ Порт у half duplex — duplex mismatch або дуже старий пристрій; дає втрати й «повільно».")
    if (mau.get("late_coll") or 0) > 0:
        out.append(f"⚠️ Late collisions ×{mau['late_coll']} — класична ознака duplex mismatch.")
    if (p.get("in_err") or 0) > 0 or (edge.get("in_err") or 0) > 1000 or (mau.get("fcs") or 0) > 1000:
        out.append(f"⚠️ Помилки прийому (за останнє опитування {p.get('in_err') or 0}, лічильник {edge.get('in_err')}, FCS {mau.get('fcs')}) — "
                   "кабель/розетка/наводки або карта.")
    if (p.get("out_disc") or 0) > 100:
        out.append(f"📈 Вихідні відкидання ×{p['out_disc']} за опитування — порт перевантажений (мікросплески/мала швидкість).")
    if (p.get("util_pct") or 0) >= 70:
        out.append(f"📈 Порт завантажений на {p['util_pct']}% від {speed} Мбіт/с — «повільно» через насичення лінку.")
    vl = (ln or {}).get("event_kinds", {}).get("ifVlan", 0)
    if vl or edge.get("pvid") == 500:
        out.append("🔐 Порт перемикався у VLAN 500 / з VLAN 500 (неавторизований) — 802.1X/MAB пускає не одразу або відмовляє.")
    dx = edge.get("dot1x") or {}
    if dx.get("port") == "unauthorized":
        out.append(f"🔐 802.1X на порту: {dx.get('pae')} / unauthorized — пристрій не авторизований (див. NPS).")
    if any("AAA" in s["m"] for s in (ln or {}).get("syslog_port", [])):
        out.append("🔐 Свіч пише «Blocked by AAA» для цього порту — автентифікація 802.1X/MAB не проходить.")
    if (ln or {}).get("other_ports_flapped", 0) >= 5:
        out.append(f"📍 На цьому свічі за вікно падали ще {ln['other_ports_flapped']} портів — можливо, проблема свіча/живлення/шафи, а не пристрою.")
    sw = (ln or {}).get("syslog_switch") or {}
    for k in ("петля/шторм", "STP", "PoE/живлення", "залізо (вентилятор/температура/БЖ)", "перезавантаження"):
        if sw.get(k):
            out.append(f"📍 Syslog свіча: {k} ×{sw[k]} за вікно.")
    up = ((ln or {}).get("device") or {}).get("uptime_s")
    if isinstance(up, int) and 0 < up < 3600:
        out.append(f"📍 Свіч перезавантажувався {up // 60} хв тому.")
    return out


def facts_lines(edge: dict, mau: dict, ln: dict | None, nb: dict | None) -> list[str]:
    L = []
    loc = " · ".join(x for x in [(nb or {}).get("site"), (nb or {}).get("location"), (nb or {}).get("rack") and f"шафа {nb['rack']}",
                                 ((ln or {}).get("device") or {}).get("location")] if x)
    L.append(f"Свіч {edge.get('switch')} ({((ln or {}).get('device') or {}).get('hardware') or edge.get('sysname') or ''}), порт "
             f"{edge.get('ifname')}" + (f" «{edge.get('alias')}»" if edge.get("alias") and edge.get("alias") != edge.get("ifname") else "")
             + (f"; розташування: {loc}" if loc else "") + ".")
    if (nb or {}).get("cable_to"):
        L.append(f"NetBox: кабель порту → {nb['cable_to']}.")
    dx = edge.get("dot1x") or {}
    L.append(f"Зараз (SNMP): {edge.get('oper')}, {edge.get('speed')} Мбіт/с, дуплекс {mau.get('duplex') or '?'}, PVID {edge.get('pvid')}, "
             f"лічильники помилок in {edge.get('in_err')} / out {edge.get('out_err')}"
             + (f", 802.1X {'/'.join(str(x) for x in (dx.get('pae'), dx.get('port')) if x)}" if dx and (dx.get("pae") or dx.get("port")) else "")
             + (f", останнє переключення лінку {netdiag.fmt_ago(edge['changed_ago_s'])} тому" if edge.get("changed_ago_s") is not None else "") + ".")
    if mau:
        L.append("Автоузгодження: карта рекламує до " + (f"{mau['nic_max_mbps']} Мбіт/с" if mau.get("nic_max_mbps") else "? (свіч не віддає повністю)")
                 + (f", свіч до {mau['switch_max_mbps']} Мбіт/с" if mau.get("switch_max_mbps") else "")
                 + (f", партнер автоузгодження: {mau['autoneg_partner']}" if mau.get("autoneg_partner") else "")
                 + (f"; FCS {mau['fcs']}, late collisions {mau['late_coll']}" if mau.get("fcs") is not None else "") + ".")
    if ln is None:
        L.append("LibreNMS: недоступний.")
    elif not ln:
        L.append("LibreNMS: свіча там немає.")
    else:
        p = ln.get("port") or {}
        if p:
            L.append(f"LibreNMS, останнє опитування ({netdiag.fmt_ago(p.get('poll_age_s'))} тому, період {p.get('poll_period_s')} с): "
                     f"трафік in/out {p['in_mbps']}/{p['out_mbps']} Мбіт/с (завантаження {p.get('util_pct')}%), "
                     f"помилки in/out {p.get('in_err')}/{p.get('out_err')}, відкидання in/out {p.get('in_disc')}/{p.get('out_disc')}, VLAN {p.get('vlan')}.")
        if ln.get("events"):
            L.append("Події порту: " + "; ".join(f"{e['t']} {e['m']}" for e in ln["events"][-12:]) + ".")
        else:
            L.append("Подій порту (up/down, швидкість, дуплекс, VLAN) за вікно немає.")
        if ln.get("syslog_port"):
            L.append("Syslog свіча про порт: " + "; ".join(f"{s['t']} {s['m']}" for s in ln["syslog_port"][-8:]) + ".")
        L.append(f"Свіч загалом: інших портів, що падали, {ln.get('other_ports_flapped', 0)}; syslog-рядків {ln.get('syslog_total', 0)}"
                 + (f" (помітні: {', '.join(f'{k} ×{v}' for k, v in ln['syslog_switch'].items())})" if ln.get("syslog_switch") else "")
                 + (f"; аптайм {netdiag.fmt_ago(ln['device'].get('uptime_s'))}" if (ln.get("device") or {}).get("uptime_s") else "") + ".")
    return L
