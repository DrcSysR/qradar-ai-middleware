"""Діагностика підключення пристрою за IP: Wi-Fi (Cisco WLC 3504) або дріт (свіч/порт/802.1X).

Алгоритм (запит із Google Chat-бота `netdiag_bot.py`):

  IP ─► MAC ─┬─ є в таблиці клієнтів WLC ─► Wi-Fi: точка, SSID, VLAN, RSSI/SNR, стан
             │                               політик (RUN / 8021X_REQD / DHCP_REQD …),
             │                               історія за останні N хв (знімки колектора),
             │                               радіо точки (канал, завантаження, клієнти)
             └─ інакше ─► дріт: MAC у FDB усіх свічів (паралельні SNMP GET) → крайовий
                          порт (той, за яким по LLDP немає іншого нашого свіча) → стан
                          порту, VLAN, помилки, 802.1X (IEEE8021-PAE-MIB). Якщо за портом
                          Ubiquiti/невідомий свіч — так і кажемо, без деталізації.
  + NPS (QRadar, події 6272/6273 за Calling-Station-ID = MAC): хто/як авторизувався,
    чому відмовлено (Reason Code). Повільна частина (Ariel), тому окремо (async).

Звідки MAC: ARP ядра (MLNX01/02, Cumulus, `netdiag_arp_routers`) — знімок колектора, при
промаху — живий GET; далі DHCPACK у QRadar (лог-сорс `track_dhcp_logsource`) як запасний
шлях і джерело hostname. Свічі, їхні SNMP-спільноти та місце (інвентар) — із Zabbix
(групи `netdiag_zabbix_groups`; спільноти розв'язуються з макросів хоста/шаблонів/
глобальних і в git/конфіг не потрапляють). Спільнота WLC — `netdiag_wlc_community`
(окрема RO-спільнота, на WLC обмежена IP mdlwr01 172.17.65.9).

Знімки WLC і ARP пише `netdiag_collector.py` (systemd, раз на `netdiag_poll_seconds`) у
власну БД `netdiag.db` (не ai_state.db — щоб не ділити WAL з чергою тріажу).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

import snmp_v2c as snmp

BASE_DIR = "/opt/qradar-middleware"
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
CACHE_DIR = os.path.join(BASE_DIR, "cache")

log = logging.getLogger("netdiag")

DEFAULTS = {
    "netdiag_db": os.path.join(BASE_DIR, "netdiag.db"),
    "netdiag_wlc_host": "172.17.65.4",
    "netdiag_wlc_community": "",
    "netdiag_arp_routers": ["172.17.6.1", "172.17.6.2"],
    "netdiag_zabbix_groups": ["Switches", "NetHw"],
    "netdiag_poll_seconds": 60,
    "netdiag_keep_minutes": 30,
    "netdiag_history_minutes": 15,
    "netdiag_switch_cache_minutes": 60,
    "netdiag_snmp_timeout": 1.0,
    "netdiag_snmp_workers": 32,
    "netdiag_nps_minutes": 60,
    # IP, які взагалі можна діагностувати (внутрішні мережі). Все інше — відмова.
    "netdiag_allowed_networks": ["172.17.0.0/16", "172.18.48.0/21", "192.168.48.0/21", "172.20.22.0/23"],
}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            cfg.update(json.load(fh))
    except (OSError, ValueError) as e:
        log.error(f"config.json не читається: {e}")
    return cfg


def opt(cfg: dict, key: str):
    v = cfg.get(key)
    return DEFAULTS.get(key) if v in (None, "") else v


# ============================================================================ ідентифікатори
def parse_ip(text: str, cfg: dict) -> str | None:
    """Перший IPv4 у тексті, якщо він у дозволених мережах; інакше None."""
    m = re.search(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", text or "")
    if not m:
        return None
    try:
        ip = ipaddress.IPv4Address(m.group(1))
    except ValueError:
        return None
    nets = [ipaddress.ip_network(n, strict=False) for n in opt(cfg, "netdiag_allowed_networks")]
    return str(ip) if any(ip in n for n in nets) else None


def parse_mac(text: str) -> str | None:
    m = re.search(r"(?<![0-9a-fA-F])([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2})(?![0-9a-fA-F])",
                  text or "")
    if not m:
        return None
    h = re.sub(r"[^0-9a-f]", "", m.group(1).lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else None


def mac_oid(mac: str) -> str:
    return ".".join(str(int(x, 16)) for x in mac.split(":"))


def oid_mac(parts: list[str]) -> str:
    return ":".join(f"{int(x):02x}" for x in parts)


# ============================================================================ БД знімків
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS wifi (
  ts INTEGER, mac TEXT, ip TEXT, user TEXT, ap_mac TEXT, ap_name TEXT, slot INTEGER, ssid TEXT,
  status INTEGER, pm_state TEXT, reason INTEGER, vlan INTEGER, proto INTEGER, rssi INTEGER, snr INTEGER,
  uptime INTEGER, rate TEXT, devtype TEXT, rx_bytes INTEGER, tx_bytes INTEGER);
CREATE INDEX IF NOT EXISTS wifi_mac_ts ON wifi(mac, ts);
CREATE INDEX IF NOT EXISTS wifi_ts ON wifi(ts);
CREATE TABLE IF NOT EXISTS radio (ts INTEGER, ap_mac TEXT, slot INTEGER, channel INTEGER, util INTEGER, users INTEGER);
CREATE INDEX IF NOT EXISTS radio_ap_ts ON radio(ap_mac, ts);
CREATE TABLE IF NOT EXISTS ap (ap_mac TEXT PRIMARY KEY, name TEXT, location TEXT, ip TEXT, model TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS arp (ip TEXT, mac TEXT, router TEXT, ifname TEXT, ts INTEGER, PRIMARY KEY (ip, router));
CREATE INDEX IF NOT EXISTS arp_mac ON arp(mac);
CREATE TABLE IF NOT EXISTS collector (k TEXT PRIMARY KEY, v TEXT);
"""


def db(cfg: dict) -> sqlite3.Connection:
    path = opt(cfg, "netdiag_db")
    new = not os.path.exists(path)
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA_SQL)
    if new:
        os.chmod(path, 0o640)
    return con


# ============================================================================ Zabbix: свічі
def _zbx(client: httpx.Client, url: str, token: str, method: str, params):
    r = client.post(f"{url.rstrip('/')}/api_jsonrpc.php",
                    json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json-rpc"})
    r.raise_for_status()
    body = r.json()
    if "error" in body:
        raise RuntimeError(f"Zabbix {method}: {body['error'].get('data') or body['error'].get('message')}")
    return body["result"]


def zabbix_token(cfg: dict) -> str:
    tok = (cfg.get("zabbix_api_token") or "").strip()
    if tok:
        return tok
    path = cfg.get("zabbix_api_token_file") or os.path.join(BASE_DIR, "zabbix_api_token")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


INV_KEYS = ("name", "location", "site_rack", "site_city", "site_address_a", "site_notes", "alias")


def _resolve_switches(cfg: dict) -> dict:
    url, token = cfg.get("zabbix_url") or "", zabbix_token(cfg)
    if not url or not token:
        raise RuntimeError("немає zabbix_url / токена Zabbix")
    with httpx.Client(timeout=30) as c:
        gids = [g["groupid"] for g in _zbx(c, url, token, "hostgroup.get",
                                           {"output": ["groupid"], "filter": {"name": opt(cfg, "netdiag_zabbix_groups")}})]
        hosts = _zbx(c, url, token, "host.get", {
            "groupids": gids, "output": ["host", "name", "status"],
            "selectInterfaces": ["ip", "type", "details"], "selectMacros": ["macro", "value"],
            "selectParentTemplates": ["templateid"], "selectInventory": list(INV_KEYS)})
        gmacros = {m["macro"]: m["value"] for m in _zbx(c, url, token, "usermacro.get",
                                                         {"globalmacro": True, "output": ["macro", "value"]})}
        tcache: dict[tuple, str | None] = {}

        def tmacro(tids: list[str], macro: str) -> str | None:
            key = (tuple(sorted(tids)), macro)
            if key in tcache:
                return tcache[key]
            seen, cur, val = set(), list(tids), None
            while cur and val is None:
                cur = [t for t in cur if t not in seen]
                seen.update(cur)
                if not cur:
                    break
                m = _zbx(c, url, token, "usermacro.get", {"hostids": cur, "filter": {"macro": macro}, "output": ["value"]})
                if m:
                    val = m[0]["value"]
                    break
                cur = [p["templateid"] for t in _zbx(c, url, token, "template.get",
                                                    {"templateids": cur, "selectParentTemplates": ["templateid"]})
                       for p in t["parentTemplates"]]
            tcache[key] = val if val is not None else gmacros.get(macro)
            return tcache[key]

        out = {}
        for h in hosts:
            # вимкнені в Zabbix хости НЕ відкидаємо: 6.117 (свіч WLC) вимкнений у моніторингу, але живий;
            # мертві просто відпадуть по таймауту SNMP
            inv = h["inventory"] if isinstance(h.get("inventory"), dict) else {}
            for i in h["interfaces"]:
                if i["type"] != "2" or i["ip"] in out:
                    continue
                comm = (i.get("details") or {}).get("community", "")
                if comm.startswith("{$"):
                    hm = {m["macro"]: m["value"] for m in h.get("macros", [])}
                    comm = hm.get(comm) or tmacro([t["templateid"] for t in h["parentTemplates"]], comm) or ""
                if not comm:
                    continue
                out[i["ip"]] = {"host": h["host"], "name": h["name"], "community": comm,
                                "inv": {k: v for k, v in inv.items() if k in INV_KEYS and v}}
        return out


def switches(cfg: dict, force: bool = False) -> dict:
    """ip → {host, name, community, inv}; кеш на диску (600, містить спільноти)."""
    path = os.path.join(CACHE_DIR, "netdiag_switches.json")
    ttl = float(opt(cfg, "netdiag_switch_cache_minutes")) * 60
    if not force and os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl:
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            pass
    try:
        data = _resolve_switches(cfg)
    except Exception as e:
        log.error(f"Zabbix: список свічів не отримано: {e}")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)  # застарілий кеш кращий за нічого
        return {}
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)
    os.replace(tmp, path)
    return data


INV_JUNK = re.compile(r"^(beijing china|default location|unknown|-)$", re.I)  # заводські sysLocation


def inv_text(inv: dict) -> str:
    parts = [inv.get(k) for k in ("site_city", "site_address_a", "site_rack", "location")
             if inv.get(k) and not INV_JUNK.match(inv[k].strip())]
    out = ", ".join(dict.fromkeys(parts))
    if inv.get("site_notes"):
        out += f" ({inv['site_notes'][:80]})"
    return out


# ============================================================================ OID-и
O_SYSNAME = "1.3.6.1.2.1.1.5.0"
O_SYSUPTIME = "1.3.6.1.2.1.1.3.0"
O_ARP = "1.3.6.1.2.1.4.22.1.2"                 # ipNetToMediaPhysAddress.<ifIndex>.<ip>
O_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"
O_IFALIAS = "1.3.6.1.2.1.31.1.1.1.18"
O_IFHIGHSPEED = "1.3.6.1.2.1.31.1.1.1.15"
O_IFOPER = "1.3.6.1.2.1.2.2.1.8"
O_IFADMIN = "1.3.6.1.2.1.2.2.1.7"
O_IFLASTCHANGE = "1.3.6.1.2.1.2.2.1.9"
O_IFINERR = "1.3.6.1.2.1.2.2.1.14"
O_IFOUTERR = "1.3.6.1.2.1.2.2.1.20"
O_DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"   # .<mac>
O_DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"  # .<fdbId=vlan>.<mac>
O_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
O_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
O_LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"          # .<col>.<timemark>.<localport>.<idx>
O_PAE_STATE = "1.0.8802.1.1.1.1.2.1.1.1"       # dot1xAuthPaeState.<port>
O_PAE_BACKEND = "1.0.8802.1.1.1.1.2.1.1.2"
O_PAE_PORTSTATUS = "1.0.8802.1.1.1.1.2.1.1.5"  # dot1xAuthAuthControlledPortStatus

# Cisco WLC (AIRESPACE-WIRELESS-MIB / CISCO-LWAPP-DOT11-CLIENT-MIB)
W_ST = "1.3.6.1.4.1.14179.2.1.4.1"             # bsnMobileStationEntry.<col>.<mac>
W_STATS = "1.3.6.1.4.1.14179.2.1.6.1"          # bsnMobileStationStatsEntry
W_CLDC = "1.3.6.1.4.1.9.9.599.1.3.1.1"         # cldcClientEntry
W_APNAME = "1.3.6.1.4.1.14179.2.2.1.1.3"
W_APLOC = "1.3.6.1.4.1.14179.2.2.1.1.4"
W_APMODEL = "1.3.6.1.4.1.14179.2.2.1.1.16"
W_APIP = "1.3.6.1.4.1.14179.2.2.1.1.19"
W_CHANNEL = "1.3.6.1.4.1.14179.2.2.2.1.4"
W_USERS = "1.3.6.1.4.1.14179.2.2.2.1.15"
W_UTIL = "1.3.6.1.4.1.14179.2.2.13.1.3"

WIFI_COLS = {  # поле знімка → (OID колонки, тип)
    "ip": (f"{W_ST}.2", "ip"), "user": (f"{W_ST}.3", "text"), "ap_mac": (f"{W_ST}.4", "mac"),
    "slot": (f"{W_ST}.5", "int"), "ssid": (f"{W_ST}.7", "text"), "status": (f"{W_ST}.9", "int"),
    "reason": (f"{W_ST}.10", "int"), "pm_state": (f"{W_ST}.23", "text"), "vlan": (f"{W_ST}.29", "int"),
    "proto": (f"{W_ST}.30", "int"), "rssi": (f"{W_STATS}.1", "int"), "snr": (f"{W_STATS}.26", "int"),
    "rx_bytes": (f"{W_STATS}.2", "int"), "tx_bytes": (f"{W_STATS}.3", "int"),
    "uptime": (f"{W_CLDC}.15", "int"), "rate": (f"{W_CLDC}.17", "text"), "devtype": (f"{W_CLDC}.44", "text"),
}

ST_NAMES = {0: "idle", 1: "AAA pending", 2: "authenticated", 3: "associated", 4: "powersave",
            5: "disassociated", 6: "to be deleted", 7: "probing", 8: "excluded", 9: "excluded/blocklisted"}
PROTO_NAMES = {1: "802.11a", 2: "802.11b", 3: "802.11g", 4: "802.11n 2.4 ГГц", 5: "802.11n 5 ГГц",
               6: "802.11ac", 7: "802.11ax 5 ГГц", 8: "802.11ax 2.4 ГГц"}
PM_HINT = {
    "RUN": "повністю підключений",
    "8021X_REQD": "чекає 802.1X — пристрій не пройшов автентифікацію (див. NPS нижче)",
    "DHCP_REQD": "асоційований, але не отримав IP по DHCP",
    "WEBAUTH_REQD": "чекає веб-автентифікації",
    "L2AUTHCOMPLETE": "L2-автентифікація завершена, далі DHCP",
    "START": "почав підключення",
    "CENTRAL_WEB_AUTH": "центральна веб-автентифікація",
}
PAE_STATE = {1: "initialize", 2: "disconnected", 3: "connecting", 4: "authenticating", 5: "authenticated",
             6: "aborting", 7: "held", 8: "forceAuth", 9: "forceUnauth", 10: "restart"}


def _conv(v, kind):
    if kind == "mac":
        return snmp.mac_str(v)
    if kind == "text":
        return snmp.text(v)
    if kind == "ip":
        return v if isinstance(v, str) else ""
    return v if isinstance(v, int) else None


# ============================================================================ колектор (знімки)
def wlc_session(cfg: dict) -> snmp.Session | None:
    comm = cfg.get("netdiag_wlc_community") or ""
    if not comm:
        return None
    return snmp.Session(opt(cfg, "netdiag_wlc_host"), comm, timeout=3, retries=1)


def collect_wlc(cfg: dict, con: sqlite3.Connection, now: int) -> int:
    s = wlc_session(cfg)
    if s is None:
        return 0
    rows: dict[str, dict] = {}
    for oid, mac_v in s.walk(f"{W_ST}.1"):
        mac = snmp.mac_str(mac_v)
        if mac:
            rows[".".join(oid.split(".")[-6:])] = {"mac": mac}
    for field, (col, kind) in WIFI_COLS.items():
        for oid, v in s.walk(col, limit=50000):
            r = rows.get(".".join(oid.split(".")[-6:]))
            if r is not None:
                r[field] = _conv(v, kind)
    # AP: імена/локації (дешево, 114 рядків) — щоразу, щоб перейменування підхоплювались
    aps: dict[str, dict] = {}
    for col, key in ((W_APNAME, "name"), (W_APLOC, "location"), (W_APMODEL, "model"), (W_APIP, "ip")):
        for oid, v in s.walk(col):
            idx = ".".join(oid.split(".")[-6:])
            aps.setdefault(idx, {})[key] = v if isinstance(v, str) else snmp.text(v)
    ap_by_mac = {oid_mac(idx.split(".")): a for idx, a in aps.items()}
    con.executemany("INSERT OR REPLACE INTO ap(ap_mac,name,location,ip,model,ts) VALUES(?,?,?,?,?,?)",
                    [(m, a.get("name", ""), a.get("location", ""), a.get("ip", ""), a.get("model", ""), now)
                     for m, a in ap_by_mac.items()])
    radio: dict[tuple, dict] = {}
    for col, key in ((W_CHANNEL, "channel"), (W_UTIL, "util"), (W_USERS, "users")):
        for oid, v in s.walk(col):
            p = oid.split(".")
            radio.setdefault((oid_mac(p[-7:-1]), int(p[-1])), {})[key] = v if isinstance(v, int) else None
    con.executemany("INSERT INTO radio(ts,ap_mac,slot,channel,util,users) VALUES(?,?,?,?,?,?)",
                    [(now, k[0], k[1], v.get("channel"), v.get("util"), v.get("users")) for k, v in radio.items()])
    fields = ["mac", *WIFI_COLS.keys()]
    data = []
    for r in rows.values():
        r["ap_name"] = (ap_by_mac.get(r.get("ap_mac") or "") or {}).get("name", "")
        data.append((now, *[r.get(f) for f in fields], r["ap_name"]))
    con.executemany(f"INSERT INTO wifi(ts,{','.join(fields)},ap_name) VALUES({','.join('?' * (len(fields) + 2))})", data)
    return len(data)


def _arp_walk(ip: str, comm: str, timeout: float) -> list[tuple[str, str, str]]:
    s = snmp.Session(ip, comm, timeout=timeout, retries=1)
    ifnames = {oid.rsplit(".", 1)[1]: snmp.text(v) for oid, v in s.walk(O_IFNAME)}
    out = []
    for oid, v in s.walk(O_ARP, limit=100000):
        p = oid.split(".")
        mac = snmp.mac_str(v)
        if mac and mac != "00:00:00:00:00:00":
            out.append((".".join(p[-4:]), mac, ifnames.get(p[-5], p[-5])))
    return out


def collect_arp(cfg: dict, con: sqlite3.Connection, now: int) -> int:
    sw = switches(cfg)
    n = 0
    for r in opt(cfg, "netdiag_arp_routers"):
        comm = (sw.get(r) or {}).get("community")
        if not comm:
            log.warning(f"ARP: немає SNMP-спільноти для {r} у Zabbix")
            continue
        try:
            rows = _arp_walk(r, comm, 3)
        except snmp.SnmpError as e:
            log.warning(f"ARP {r}: {e}")
            continue
        con.executemany("INSERT OR REPLACE INTO arp(ip,mac,router,ifname,ts) VALUES(?,?,?,?,?)",
                        [(ip, mac, r, ifn, now) for ip, mac, ifn in rows])
        n += len(rows)
    return n


def prune(cfg: dict, con: sqlite3.Connection, now: int) -> None:
    keep = now - int(float(opt(cfg, "netdiag_keep_minutes")) * 60)
    con.execute("DELETE FROM wifi WHERE ts < ?", (keep,))
    con.execute("DELETE FROM radio WHERE ts < ?", (keep,))
    con.execute("DELETE FROM arp WHERE ts < ?", (now - 6 * 3600,))  # ARP: запасна пам'ять на 6 год


# ============================================================================ IP → MAC
def ip_to_mac(cfg: dict, ip: str) -> dict | None:
    """Свіжий ARP-запис ядра: зі знімка колектора, при промаху — живий GET."""
    con = db(cfg)
    try:
        row = con.execute("SELECT mac, router, ifname, ts FROM arp WHERE ip=? ORDER BY ts DESC LIMIT 1", (ip,)).fetchone()
    finally:
        con.close()
    if row and time.time() - row["ts"] < 3 * 60:
        return dict(row)
    sw = switches(cfg)
    for r in opt(cfg, "netdiag_arp_routers"):
        comm = (sw.get(r) or {}).get("community")
        if not comm:
            continue
        try:
            s = snmp.Session(r, comm, timeout=2, retries=1)
            # ipNetToMediaPhysAddress індексується ifIndex; ifIndex невідомий → короткий walk по IP неможливий,
            # тому беремо ifIndex зі знімка (якщо був) або обходимо таблицю цілком (~2-3 с).
            for oid, v in s.walk(O_ARP, limit=100000):
                if oid.endswith("." + ip):
                    mac = snmp.mac_str(v)
                    if mac:
                        ifn = snmp.text(s.get(f"{O_IFNAME}.{oid.split('.')[-5]}").get(f"{O_IFNAME}.{oid.split('.')[-5]}"))
                        return {"mac": mac, "router": r, "ifname": ifn, "ts": int(time.time())}
        except snmp.SnmpError as e:
            log.warning(f"ARP live {r}: {e}")
    return dict(row) if row else None


def wifi_by_ip(cfg: dict, ip: str) -> dict | None:
    """Останній знімок WLC з цим IP (за 10 хв) — запасний шлях IP → MAC поза ARP ядра."""
    con = db(cfg)
    try:
        row = con.execute("SELECT mac, vlan, ts FROM wifi WHERE ip=? AND ts>=? ORDER BY ts DESC LIMIT 1",
                          (ip, int(time.time()) - 600)).fetchone()
    finally:
        con.close()
    return dict(row) if row else None


def mac_to_ips(cfg: dict, mac: str) -> list[str]:
    con = db(cfg)
    try:
        return [r["ip"] for r in con.execute("SELECT DISTINCT ip FROM arp WHERE mac=? ORDER BY ts DESC", (mac,))]
    finally:
        con.close()


def vlan_from_ifname(ifname: str) -> int | None:
    m = re.search(r"(?:vlan|Vlan|vl|bridge\.)(\d{1,4})(?:-v\d+)?$", ifname or "")
    return int(m.group(1)) if m else None


# ============================================================================ Wi-Fi
def wifi_live(cfg: dict, mac: str) -> dict | None:
    """Поточний запис клієнта прямо з WLC (GET за індексом MAC)."""
    s = wlc_session(cfg)
    if s is None:
        return None
    idx = mac_oid(mac)
    try:
        got = s.get(f"{W_ST}.1.{idx}")
        if not got:
            return None
        oids = {f: f"{col}.{idx}" for f, (col, _) in WIFI_COLS.items()}
        vals = {}
        items = list(oids.items())
        for i in range(0, len(items), 10):
            chunk = items[i:i + 10]
            r = s.get(*[o for _, o in chunk])
            for f, o in chunk:
                if o in r:
                    vals[f] = _conv(r[o], WIFI_COLS[f][1])
        vals["mac"] = mac
        if vals.get("ap_mac"):
            api = mac_oid(vals["ap_mac"])
            ar = s.get(f"{W_APNAME}.{api}", f"{W_APLOC}.{api}")
            vals["ap_name"] = snmp.text(ar.get(f"{W_APNAME}.{api}"))
            vals["ap_location"] = snmp.text(ar.get(f"{W_APLOC}.{api}"))
            slot = vals.get("slot") or 0
            rr = s.get(f"{W_CHANNEL}.{api}.{slot}", f"{W_UTIL}.{api}.{slot}", f"{W_USERS}.{api}.{slot}")
            vals["channel"] = rr.get(f"{W_CHANNEL}.{api}.{slot}")
            vals["util"] = rr.get(f"{W_UTIL}.{api}.{slot}")
            vals["ap_users"] = rr.get(f"{W_USERS}.{api}.{slot}")
        return vals
    except snmp.SnmpError as e:
        log.warning(f"WLC live: {e}")
        return {"error": str(e)}


def wifi_history(cfg: dict, mac: str, minutes: float) -> list[dict]:
    con = db(cfg)
    try:
        since = int(time.time() - minutes * 60)
        rows = [dict(r) for r in con.execute("SELECT * FROM wifi WHERE mac=? AND ts>=? ORDER BY ts", (mac, since))]
        snaps = [r["ts"] for r in con.execute("SELECT DISTINCT ts FROM wifi WHERE ts>=? ORDER BY ts", (since,))]
    finally:
        con.close()
    present = {r["ts"] for r in rows}
    # знімки, де клієнта НЕ було (відвалювався) — як рядки-маркери
    for t in snaps:
        if t not in present:
            rows.append({"ts": t, "absent": True})
    return sorted(rows, key=lambda r: r["ts"])


def summarize_history(hist: list[dict]) -> dict:
    seen = [r for r in hist if not r.get("absent")]
    if not hist:
        return {"snapshots": 0}
    aps, roams, prev = [], 0, None
    for r in seen:
        if r["ap_name"] != prev:
            if prev is not None:
                roams += 1
            aps.append((r["ts"], r["ap_name"], r.get("slot")))
            prev = r["ap_name"]
    rssi = [r["rssi"] for r in seen if isinstance(r.get("rssi"), int) and r["rssi"] < 0]
    snr = [r["snr"] for r in seen if isinstance(r.get("snr"), int) and r["snr"] > 0]
    gaps = sum(1 for r in hist if r.get("absent"))
    reconnects = 0
    for a, b in zip(seen, seen[1:]):
        if isinstance(a.get("uptime"), int) and isinstance(b.get("uptime"), int) and b["uptime"] < a["uptime"]:
            reconnects += 1
    states = sorted({r.get("pm_state") for r in seen if r.get("pm_state")})
    return {"snapshots": len(hist), "present": len(seen), "absent": gaps, "roams": roams, "aps": aps,
            "reconnects": reconnects, "states": states,
            "rssi": (min(rssi), round(sum(rssi) / len(rssi)), max(rssi)) if rssi else None,
            "snr": (min(snr), round(sum(snr) / len(snr)), max(snr)) if snr else None,
            "first": hist[0]["ts"], "last": hist[-1]["ts"],
            # похвилинний ряд для картки: (ts, rssi | None якщо клієнта не було, точка)
            "series": [(r["ts"], None if r.get("absent") else r.get("rssi"), r.get("ap_name", "")) for r in hist]}


def wifi_verdict(cur: dict | None, summ: dict) -> list[str]:
    """Прості евристики → висновки людською мовою."""
    out = []
    if cur and not cur.get("error"):
        pm = cur.get("pm_state") or ""
        if pm and pm != "RUN":
            out.append(f"⚠️ Стан на WLC `{pm}` — {PM_HINT.get(pm, 'не завершив підключення')}.")
        if cur.get("status") in (8, 9):
            out.append("⛔ Клієнт у списку виключених WLC (exclusion) — забагато невдалих спроб автентифікації/асоціації.")
        rssi, snr = cur.get("rssi"), cur.get("snr")
        if isinstance(rssi, int) and rssi < 0:
            if rssi <= -75:
                out.append(f"📶 Дуже слабкий сигнал ({rssi} dBm) — пристрій далеко від точки або за перешкодою.")
            elif rssi <= -67:
                out.append(f"📶 Посередній сигнал ({rssi} dBm) — для голосу/відео замало (бажано ≥ −67).")
        if isinstance(snr, int) and 0 < snr < 20:
            out.append(f"📉 Низький SNR ({snr} dB) — шум/завади в ефірі.")
        if isinstance(cur.get("util"), int) and cur["util"] >= 60:
            out.append(f"🚦 Канал точки завантажений на {cur['util']}% — ефір перевантажений.")
        if cur.get("slot") == 0:
            out.append("ℹ️ Пристрій на 2.4 ГГц — повільніше і більше завад, ніж 5 ГГц.")
    if summ.get("roams", 0) >= 3:
        out.append(f"🔁 {summ['roams']} переходів між точками за вікно — «пінг-понг» роумінгу (межа покриття).")
    if summ.get("reconnects", 0) >= 1 or summ.get("absent", 0) >= 2:
        out.append(f"🔌 Перепідключення: {summ.get('reconnects', 0)}, пропущених знімків: {summ.get('absent', 0)} — з'єднання рветься.")
    if not out and cur and not cur.get("error"):
        out.append("✅ З боку Wi-Fi проблем не видно: стан RUN, сигнал і завантаження в нормі.")
    return out


# ============================================================================ дріт
def _probe_fdb(item, mac_idx: str, vlan: int | None, timeout: float):
    ip, info = item
    s = snmp.Session(ip, info["community"], timeout=timeout, retries=1)
    oids = [O_SYSNAME, f"{O_DOT1D_FDB_PORT}.{mac_idx}"]
    if vlan:
        oids.append(f"{O_DOT1Q_FDB_PORT}.{vlan}.{mac_idx}")
    try:
        r = s.get(*oids)
    except snmp.SnmpError as e:
        return ip, None, str(e)
    port = r.get(f"{O_DOT1D_FDB_PORT}.{mac_idx}")
    if not isinstance(port, int) and vlan:
        port = r.get(f"{O_DOT1Q_FDB_PORT}.{vlan}.{mac_idx}")
    return ip, {"sysname": snmp.text(r.get(O_SYSNAME)), "bport": port if isinstance(port, int) and port > 0 else None}, None


def _lldp_on_port(s: snmp.Session, bport: int, ifindex: int | None) -> tuple[bool, list[dict]]:
    """(чи віддає свіч LLDP-MIB взагалі, сусіди на порту). lldpRemLocalPortNum на HP = номер
    bridge-порту, на інших — ifIndex; беремо обидва. Huawei/Cumulus по нашій спільноті LLDP
    не віддають — тоді (False, [])."""
    want = {str(bport)} | ({str(ifindex)} if ifindex else set())
    try:
        names = s.walk(f"{O_LLDP_REM}.9", limit=5000)
    except snmp.SnmpError:
        return False, []
    if not names:
        return False, []
    out = []
    for oid, v in names:
        p = oid.split(".")
        if p[-2] not in want:
            continue
        idx = ".".join(p[-3:])
        try:
            r = s.get(f"{O_LLDP_REM}.10.{idx}", f"{O_LLDP_REM}.12.{idx}", f"{O_LLDP_REM}.8.{idx}", f"{O_LLDP_REM}.7.{idx}")
        except snmp.SnmpError:
            r = {}
        caps = r.get(f"{O_LLDP_REM}.12.{idx}", b"")
        b0 = caps[0] if isinstance(caps, (bytes, bytearray)) and caps else 0
        out.append({"sysname": snmp.text(v), "sysdesc": snmp.text(r.get(f"{O_LLDP_REM}.10.{idx}"))[:120],
                    "port": snmp.text(r.get(f"{O_LLDP_REM}.8.{idx}")) or snmp.text(r.get(f"{O_LLDP_REM}.7.{idx}")),
                    "bridge": bool(b0 & 0x20), "router": bool(b0 & 0x08), "ap": bool(b0 & 0x10), "phone": bool(b0 & 0x04)})
    return True, out


def _norm(x: str) -> str:
    return re.sub(r"[^0-9a-z]", "", (x or "").lower())


UBNT_RE = re.compile(r"ubiquiti|ubnt|edgeswitch|unifi|\busw\b|US-\d|USW-", re.I)
WLC_RE = re.compile(r"cisco_3504|cisco controller|AIR-CT", re.I)


def _port_detail(ip: str, info: dict, bport: int, timeout: float) -> dict:
    s = snmp.Session(ip, info["community"], timeout=max(timeout, 2), retries=1)
    r = s.get(f"{O_BASEPORT_IFINDEX}.{bport}", O_SYSUPTIME)
    ifindex = r.get(f"{O_BASEPORT_IFINDEX}.{bport}")
    ifindex = ifindex if isinstance(ifindex, int) and ifindex > 0 else bport
    up = r.get(O_SYSUPTIME) if isinstance(r.get(O_SYSUPTIME), int) else None
    q = s.get(f"{O_IFNAME}.{ifindex}", f"{O_IFALIAS}.{ifindex}", f"{O_IFOPER}.{ifindex}", f"{O_IFADMIN}.{ifindex}",
              f"{O_IFHIGHSPEED}.{ifindex}", f"{O_IFLASTCHANGE}.{ifindex}", f"{O_IFINERR}.{ifindex}",
              f"{O_IFOUTERR}.{ifindex}", f"{O_PVID}.{bport}")
    d = {"ifindex": ifindex, "bport": bport,
         "ifname": snmp.text(q.get(f"{O_IFNAME}.{ifindex}")) or f"port {bport}",
         "alias": snmp.text(q.get(f"{O_IFALIAS}.{ifindex}")),
         "oper": {1: "up", 2: "down"}.get(q.get(f"{O_IFOPER}.{ifindex}"), str(q.get(f"{O_IFOPER}.{ifindex}"))),
         "admin": {1: "enabled", 2: "disabled"}.get(q.get(f"{O_IFADMIN}.{ifindex}"), ""),
         "speed": q.get(f"{O_IFHIGHSPEED}.{ifindex}"),
         "in_err": q.get(f"{O_IFINERR}.{ifindex}"), "out_err": q.get(f"{O_IFOUTERR}.{ifindex}"),
         "pvid": q.get(f"{O_PVID}.{bport}")}
    lc = q.get(f"{O_IFLASTCHANGE}.{ifindex}")
    if isinstance(lc, int) and up:
        d["changed_ago_s"] = max(0, (up - lc) // 100)
    try:
        pae = s.get(f"{O_PAE_STATE}.{bport}", f"{O_PAE_PORTSTATUS}.{bport}")
        if pae:
            d["dot1x"] = {"pae": PAE_STATE.get(pae.get(f"{O_PAE_STATE}.{bport}"), pae.get(f"{O_PAE_STATE}.{bport}")),
                          "port": {1: "authorized", 2: "unauthorized"}.get(pae.get(f"{O_PAE_PORTSTATUS}.{bport}"), None)}
    except snmp.SnmpError:
        pass
    d["lldp_visible"], d["lldp"] = _lldp_on_port(s, bport, ifindex)
    return d


def wired_trace(cfg: dict, mac: str, vlan: int | None) -> dict:
    sw = switches(cfg)
    if not sw:
        return {"error": "немає списку свічів із Zabbix"}
    timeout = float(opt(cfg, "netdiag_snmp_timeout"))
    mac_idx = mac_oid(mac)
    hits, silent = {}, []
    with ThreadPoolExecutor(int(opt(cfg, "netdiag_snmp_workers"))) as ex:
        for ip, res, err in ex.map(lambda it: _probe_fdb(it, mac_idx, vlan, timeout), sw.items()):
            if err:
                silent.append(sw[ip]["name"])
            elif res and res["bport"]:
                hits[ip] = res
    if not hits:
        return {"found": False, "silent": silent}
    with ThreadPoolExecutor(8) as ex:
        details = dict(zip(hits, ex.map(lambda ip: _safe_port(ip, sw[ip], hits[ip]["bport"], timeout), hits)))
    # Транзитний порт = за ним інший наш свіч, де цей MAC теж видно. Ознаки: LLDP-сусід (лише HP
    # віддають LLDP-MIB) або опис порту (ifAlias), у якому записане ім'я сусіднього свіча —
    # на Huawei-стеку саме так: «HPE-2530-86-R010102:28». Решта хітів — кандидати на край.
    hit_keys = {}
    for ip in hits:
        for nm in (hits[ip]["sysname"], sw[ip]["name"], sw[ip]["host"]):
            if len(_norm(nm)) >= 6:
                hit_keys[_norm(nm)] = ip

    def leads_to_other(ip: str, d: dict) -> bool:
        cands = [n["sysname"] for n in d.get("lldp", [])] + [d.get("alias", "")]
        for c in cands:
            nc = _norm(c)
            for k, other in hit_keys.items():
                if other != ip and k and (k in nc or (len(nc) >= 6 and nc in k)):
                    return True
        return False

    core = set(opt(cfg, "netdiag_arp_routers"))
    edges = [ip for ip, d in details.items() if not d.get("error") and not leads_to_other(ip, d)]
    # кілька кандидатів: спершу свічі, що віддають LLDP (там «немає свіча-сусіда» — підтверджений факт),
    # потім решта; ядро — в кінці
    edges.sort(key=lambda ip: (ip in core, not details[ip].get("lldp_visible"), ip))
    path = [{"ip": ip, "switch": sw[ip]["name"], "sysname": hits[ip]["sysname"], "port": details[ip].get("ifname")}
            for ip in hits]
    if not edges:
        return {"found": True, "edge": None, "path": path, "silent": silent}
    eip = edges[0]
    d = details[eip]
    behind = None
    for n in d.get("lldp", []):
        if WLC_RE.search(n["sysname"] + " " + n["sysdesc"]):
            behind = {"kind": "wlc", **n}
        elif UBNT_RE.search(n["sysname"] + " " + n["sysdesc"]):
            behind = {"kind": "ubiquiti", **n}
        elif n["bridge"] and not n["phone"] and not n["ap"]:
            behind = behind or {"kind": "switch", **n}
        elif n["phone"]:
            behind = behind or {"kind": "phone", **n}
        elif n["ap"]:
            behind = behind or {"kind": "ap", **n}
    return {"found": True, "edge": {"ip": eip, "switch": sw[eip]["name"], "host": sw[eip]["host"],
                                    "sysname": hits[eip]["sysname"], "location": inv_text(sw[eip].get("inv", {})),
                                    **d},
            "behind": behind, "path": path, "silent": silent,
            # показуємо інших кандидатів лише коли вибір справді неоднозначний (обидва з LLDP або край без LLDP)
            "other_edges": [sw[i]["name"] for i in edges[1:]
                            if details[i].get("lldp_visible") or not d.get("lldp_visible")]}


def _safe_port(ip, info, bport, timeout):
    try:
        return _port_detail(ip, info, bport, timeout)
    except snmp.SnmpError as e:
        return {"error": str(e), "lldp": []}


# ============================================================================ QRadar: NPS і DHCP
NPS_FIELDS = {
    "account": r"Fully Qualified Account Name:\s+(\S+)",
    "called": r"Called Station Identifier:\s+(\S+)",
    "nas_id": r"NAS Identifier:\s+(\S+)",
    "nas_ip": r"NAS IPv4 Address:\s+(\S+)",
    "port_type": r"NAS Port-Type:\s+(.+?)\s{2,}",
    "client": r"Client Friendly Name:\s+(\S+)",
    "policy": r"Network Policy Name:\s+(.+?)\s{2,}",
    "auth_type": r"Authentication Type:\s+(\S+)",
    "eap": r"EAP Type:\s+(.+?)\s{2,}",
    "reason_code": r"Reason Code:\s+(\d+)",
    "reason": r"Reason:\s+(.+?)(?:\s{2,}|\\n|$)",
    "server": r"Authentication Server:\s+(\S+)",
}
NPS_QIDS = ("Failure Audit: Network Policy Server denied access to a user",
            "Success Audit: Network Policy Server granted access to a user")


def nps_aql(mac: str, minutes: int) -> str:
    dashed = mac.replace(":", "-")
    q = ", ".join(f"'{x}'" for x in NPS_QIDS)
    return ("SELECT starttime AS ts, QIDNAME(qid) AS q, LOGSOURCENAME(logsourceid) AS ls, UTF8(payload) AS p "
            f"FROM events WHERE QIDNAME(qid) IN ({q}) "
            f"AND UTF8(payload) ILIKE '%Calling Station Identifier:  {dashed}%' "
            f"ORDER BY starttime DESC LIMIT 200 LAST {max(1, int(minutes))} MINUTES")


def parse_nps(ev: dict) -> dict:
    p = ev.get("p") or ""
    d = {"ts": int(ev.get("ts") or 0), "ok": "granted" in (ev.get("q") or ""), "ls": ev.get("ls") or ""}
    for k, rx in NPS_FIELDS.items():
        m = re.search(rx, p)
        d[k] = m.group(1).strip() if m else ""
    return d


def dhcp_aql(ip: str, mac: str | None, hours: int, logsource: str) -> str:
    conds = [f"UTF8(payload) ILIKE '%DHCPACK on {ip} to %'"]
    if mac:
        conds.append(f"UTF8(payload) ILIKE '% {mac} %'")
    ls = logsource.replace("'", "''")
    return ("SELECT starttime AS ts, UTF8(payload) AS p FROM events "
            f"WHERE LOGSOURCENAME(logsourceid) ILIKE '{ls}' AND QIDNAME(qid) = 'DHCPACK' "
            f"AND ({' OR '.join(conds)}) ORDER BY starttime DESC LIMIT 20 LAST {max(1, int(hours))} HOURS")


DHCP_RE = re.compile(r"DHCPACK on ([\d.]+) to ([0-9a-f:]{17})(?: \(([^)]*)\))? via ([\d.]+|\w+)", re.I)


# ============================================================================ зведення
def fmt_ago(sec) -> str:
    if not isinstance(sec, (int, float)):
        return "?"
    sec = int(sec)
    if sec < 90:
        return f"{sec} с"
    if sec < 5400:
        return f"{sec // 60} хв"
    if sec < 2 * 86400:
        return f"{sec // 3600} год"
    return f"{sec // 86400} дн"


def hhmm(ts: int) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


def diagnose_fast(cfg: dict, query: str) -> dict:
    """Синхронна частина (SNMP + знімки): ~1–5 с. Повертає структуру для рендера."""
    ip = parse_ip(query, cfg)
    mac = parse_mac(query)
    res = {"query": query, "ip": ip, "mac": mac, "ts": int(time.time())}
    if not ip and not mac:
        res["error"] = "no_target"
        return res
    if ip and not mac:
        a = ip_to_mac(cfg, ip)
        if a:
            res.update(mac=a["mac"], arp=a)
            res["vlan"] = vlan_from_ifname(a.get("ifname", ""))
        else:
            # Гостьовий VLAN 500 (172.18.48/21) і VLAN точок маршрутизує Palo Alto, а не ядро MLNX —
            # ARP там немає. Wi-Fi-клієнтів таких мереж знає WLC (IP є в його таблиці клієнтів).
            w = wifi_by_ip(cfg, ip)
            if w:
                res.update(mac=w["mac"], arp={"mac": w["mac"], "router": "WLC", "ifname": f"vlan{w.get('vlan')}", "ts": w["ts"]})
    if mac and not ip:
        ips = mac_to_ips(cfg, mac)
        res["ip"] = ips[0] if ips else None
    mac = res.get("mac")
    if not mac:
        res["medium"] = "unknown"
        return res
    hist_min = float(opt(cfg, "netdiag_history_minutes"))
    cur = wifi_live(cfg, mac)
    hist = wifi_history(cfg, mac, hist_min)
    summ = summarize_history(hist)
    if cur and not cur.get("error"):
        res.update(medium="wifi", wifi=cur, history=summ)
        res["verdict"] = wifi_verdict(cur, summ)
        return res
    if summ.get("present"):
        # зараз на WLC його немає, але за вікно був → відвалився від Wi-Fi
        last = [r for r in hist if not r.get("absent")][-1]
        res.update(medium="wifi_gone", wifi=last, history=summ)
        res["verdict"] = [f"⚠️ Зараз пристрою на WLC немає; востаннє бачили о {hhmm(last['ts'])} на {last.get('ap_name')}."] + \
            wifi_verdict(None, summ)
        return res
    tr = wired_trace(cfg, mac, res.get("vlan"))
    res.update(medium="wired", wired=tr)
    v = []
    e = tr.get("edge") or {}
    b = tr.get("behind") or {}
    if not tr.get("found"):
        v.append("❓ MAC не знайдено в жодній таблиці комутації — пристрій зараз неактивний або за свічем без SNMP.")
    elif b.get("kind") == "wlc":
        res["medium"] = "wifi_unknown"
        v.append("📡 MAC видно за WLC, але в таблиці клієнтів його немає — підключається до Wi-Fi і не завершує асоціацію.")
    elif e:
        if e.get("oper") == "down":
            v.append("🔌 Порт зараз down — кабель/пристрій відключено.")
        if (e.get("in_err") or 0) + (e.get("out_err") or 0) > 1000:
            v.append(f"⚠️ Помилки на порту: in {e.get('in_err')}, out {e.get('out_err')} — кабель/розетка/дуплекс.")
        if isinstance(e.get("speed"), int) and 0 < e["speed"] < 1000:
            v.append(f"🐢 Порт піднявся на {e['speed']} Мбіт/с — зазвичай кабель (пошкоджена пара) або старий NIC.")
        dx = e.get("dot1x") or {}
        if dx.get("port") == "unauthorized" or dx.get("pae") in ("held", "connecting", "authenticating"):
            v.append(f"🔐 802.1X на порту: {dx.get('pae')} / {dx.get('port')} — пристрій не авторизований (причина — NPS нижче).")
        if e.get("pvid") == 500:
            v.append("🔐 Порт у VLAN 500 (Unauthenticated) — пристрій не пройшов 802.1X/MAB.")
        if not v:
            v.append("✅ З боку комутатора проблем не видно: порт up, без помилок.")
    res["verdict"] = v
    return res


def render_fast(res: dict) -> str:
    q = res.get("query", "")
    if res.get("error") == "no_target":
        return ("Надішліть IP (або MAC) пристрою, напр. `172.17.104.25`. "
                "Діагностуються лише внутрішні мережі.")
    head = f"*Діагностика* `{res.get('ip') or '—'}`"
    if res.get("mac"):
        head += f" · MAC `{res['mac']}`"
    lines = [head]
    if not res.get("mac"):
        lines.append("❓ Для цього IP немає запису ARP на ядрі (MLNX01/02) — пристрій зараз не в мережі "
                     "або IP статичний і неактивний. Перевіряю DHCP у QRadar…")
        return "\n".join(lines)
    m = res.get("medium")
    if m in ("wifi", "wifi_gone"):
        w = res["wifi"]
        lines.append(f"📡 *Wi-Fi* — точка *{w.get('ap_name') or w.get('ap_mac')}*"
                     + (f" ({w['ap_location']})" if w.get("ap_location") and w.get("ap_location") not in ("default location", "") else ""))
        band = "2.4 ГГц" if w.get("slot") == 0 else "5 ГГц" if w.get("slot") == 1 else f"radio {w.get('slot')}"
        lines.append(f"SSID `{w.get('ssid')}` · VLAN {w.get('vlan')} · {band}"
                     + (f", канал {w['channel']}" if w.get("channel") else "")
                     + (f" · {PROTO_NAMES.get(w.get('proto'), '')}" if w.get("proto") in PROTO_NAMES else ""))
        lines.append(f"Сигнал {w.get('rssi')} dBm · SNR {w.get('snr')} dB · rate {w.get('rate') or '?'}"
                     + (f" · завантаження каналу {w['util']}%, клієнтів на радіо {w.get('ap_users')}" if w.get("util") is not None else ""))
        st = ST_NAMES.get(w.get("status"), w.get("status"))
        lines.append(f"Стан: `{w.get('pm_state') or '?'}` ({st}) · підключений {fmt_ago(w.get('uptime'))}"
                     + (f" · користувач `{w['user']}`" if w.get("user") else "")
                     + (f" · {w['devtype']}" if w.get("devtype") and w["devtype"] != "Unclassified" else ""))
        h = res.get("history") or {}
        if h.get("snapshots"):
            aps = " → ".join(f"{a[1]} ({hhmm(a[0])})" for a in h.get("aps", [])) or "—"
            lines.append(f"*Історія {round((h['last'] - h['first']) / 60) or 1} хв* ({h['present']}/{h['snapshots']} знімків): {aps}")
            if h.get("rssi"):
                lines.append(f"RSSI мін/сер/макс {h['rssi'][0]}/{h['rssi'][1]}/{h['rssi'][2]} dBm"
                             + (f" · SNR {h['snr'][0]}/{h['snr'][1]}/{h['snr'][2]} dB" if h.get("snr") else "")
                             + f" · роумінгів {h['roams']} · перепідключень {h['reconnects']}")
        else:
            lines.append("_Історії ще немає (колектор знімає раз на хвилину)._")
    elif m in ("wired", "wifi_unknown"):
        tr = res.get("wired") or {}
        e = tr.get("edge")
        b = tr.get("behind") or {}
        if e:
            if b.get("kind") == "ubiquiti":
                lines.append(f"🔌 *Дріт* — за PoE-свічем Ubiquiti *{b.get('sysname') or '?'}*, "
                             f"який підключений до *{e['switch']}* порт `{e['ifname']}`"
                             + (f" — {e['location']}" if e.get("location") else ""))
            else:
                lines.append(f"🔌 *Дріт* — свіч *{e['switch']}* (`{e['ip']}`) порт *`{e['ifname']}`*"
                             + (f" «{e['alias']}»" if e.get("alias") else ""))
                if e.get("location"):
                    lines.append(f"📍 {e['location']}")
                sp = f"{e['speed']} Мбіт/с" if e.get("speed") else "?"
                lines.append(f"Порт {e.get('oper')} ({e.get('admin')}) · {sp} · VLAN {e.get('pvid')} · "
                             f"змінився {fmt_ago(e.get('changed_ago_s'))} тому · помилки in/out {e.get('in_err')}/{e.get('out_err')}")
                dx = e.get("dot1x")
                if dx and dx.get("pae"):
                    lines.append(f"802.1X: `{dx.get('pae')}` / `{dx.get('port') or '?'}`")
                if b.get("kind") == "phone":
                    lines.append(f"☎️ Підключений через IP-телефон {b.get('sysname')}")
                elif b.get("kind") == "switch":
                    lines.append(f"🔀 За портом некерований/невідомий свіч *{b.get('sysname') or b.get('sysdesc')[:40]}* — далі не видно.")
            if tr.get("other_edges"):
                lines.append(f"_Інші кандидати: {', '.join(tr['other_edges'][:3])}_")
        elif tr.get("found"):
            lines.append("🔌 MAC видно лише на транзитних портах: " + ", ".join(f"{p['switch']} {p['port']}" for p in tr.get("path", [])[:4]))
        elif tr.get("error"):
            lines.append(f"⚠️ {tr['error']}")
    for v in res.get("verdict") or []:
        lines.append(v)
    return "\n".join(lines)


# ============================================================================ картка Google Chat (cardsV2)
GREEN, AMBER, RED, GREY = "#188038", "#E37400", "#D93025", "#5F6368"


def _e(x) -> str:
    """Екранування значень з обладнання (імена AP, ifAlias, логіни) перед вставкою в HTML картки."""
    import html
    return html.escape("" if x is None else str(x), quote=False)


def _c(text, color: str) -> str:
    return f'<font color="{color}">{text}</font>'


def lvl_rssi(v) -> str:
    if not isinstance(v, int) or v >= 0:
        return GREY
    return GREEN if v > -67 else AMBER if v > -75 else RED


def lvl_snr(v) -> str:
    if not isinstance(v, int) or v <= 0:
        return GREY
    return GREEN if v >= 25 else AMBER if v >= 15 else RED


def lvl_util(v) -> str:
    if not isinstance(v, int):
        return GREY
    return GREEN if v < 40 else AMBER if v < 60 else RED


def _rssi_word(v) -> str:
    if not isinstance(v, int) or v >= 0:
        return ""
    return "відмінний" if v > -60 else "добрий" if v > -67 else "слабкий" if v > -75 else "дуже слабкий"


def _row(label: str, text: str, icon: str | None = None, bottom: str | None = None) -> dict:
    w = {"decoratedText": {"topLabel": label, "text": text, "wrapText": True}}
    if icon:
        w["decoratedText"]["startIcon"] = {"materialIcon": {"name": icon}}
    if bottom:
        w["decoratedText"]["bottomLabel"] = bottom
    return w


def _para(text: str) -> dict:
    return {"textParagraph": {"text": text}}


def _verdict_color(v: str) -> str:
    if v.startswith("✅"):
        return GREEN
    if v.startswith(("⛔", "🔌", "❓")):
        return RED
    if v.startswith("ℹ️"):
        return GREY
    return AMBER


def _wifi_sections(res: dict) -> list[dict]:
    w = res["wifi"]
    gone = res.get("medium") == "wifi_gone"
    band = "2.4 ГГц" if w.get("slot") == 0 else "5 ГГц" if w.get("slot") == 1 else f"radio {w.get('slot')}"
    loc = w.get("ap_location")
    loc = loc if loc and loc not in ("default location",) else ""
    conn = [
        _row("Точка доступу", f"<b>{_e(w.get('ap_name') or w.get('ap_mac'))}</b>", "wifi", _e(loc) or None),
        _row("Мережа", f"SSID <b>{_e(w.get('ssid'))}</b> · VLAN {_e(w.get('vlan'))}", "lan"),
        _row("Радіо", f"{band}" + (f" · канал {w['channel']}" if w.get("channel") else "")
             + (f" · {PROTO_NAMES[w['proto']]}" if w.get("proto") in PROTO_NAMES else ""), "settings_input_antenna"),
    ]
    who = " · ".join(x for x in [_e(w.get("user")) if w.get("user") else "",
                                  _e(w.get("devtype")) if w.get("devtype") not in (None, "", "Unclassified") else ""] if x)
    if who:
        conn.append(_row("Пристрій / користувач", who, "devices"))
    if not gone:
        conn.append(_row("Підключений", fmt_ago(w.get("uptime")), "schedule"))
    sections = [{"header": "📡 Wi-Fi" + (" — зараз НЕ підключений" if gone else ""), "widgets": conn}]

    rssi, snr, util = w.get("rssi"), w.get("snr"), w.get("util")
    sig = [
        _row("Сигнал (RSSI)", _c(f"<b>{_e(rssi)} dBm</b> — {_rssi_word(rssi)}", lvl_rssi(rssi)), "signal_cellular_alt",
             "норма ≥ −67 · слабкий −67…−75 · погано < −75"),
        _row("Шум (SNR)", _c(f"<b>{_e(snr)} dB</b>", lvl_snr(snr)), "graphic_eq", "норма ≥ 25 · гранично 15…25 · погано < 15"),
    ]
    if util is not None:
        sig.append(_row("Завантаження каналу", _c(f"<b>{util}%</b>", lvl_util(util))
                        + f" · клієнтів на радіо {_e(w.get('ap_users'))}", "network_check"))
    if w.get("rate"):
        sig.append(_row("Швидкість (rate / MCS)", _e(w.get("rate")), "speed"))
    pm = w.get("pm_state") or ""
    st_txt = _c(f"<b>{_e(pm or '?')}</b>", GREEN if pm == "RUN" else RED)
    if pm and pm != "RUN":
        st_txt += " — " + _e(PM_HINT.get(pm, "не завершив підключення"))
    elif pm == "RUN":
        st_txt += " — повністю підключений"
    sig.append(_row("Стан на контролері", st_txt, "verified" if pm == "RUN" else "error"))
    sections.append({"header": "📶 Сигнал і стан" + (" (останній знімок)" if gone else ""), "widgets": sig})

    h = res.get("history") or {}
    if h.get("snapshots"):
        mins = round((h["last"] - h["first"]) / 60) or 1
        hw = []
        series = h.get("series") or []
        if series:
            cells = []
            for ts, r, _ap in series[-15:]:
                cells.append(_c("✕", RED) if r is None else _c(str(r), lvl_rssi(r)))
            hw.append(_row(f"RSSI похвилинно ({hhmm(series[max(0, len(series) - 15)][0])} → {hhmm(series[-1][0])})",
                           " ".join(cells), "show_chart", "✕ — клієнта не було на WLC"))
        if h.get("rssi"):
            mn, avg, mx = h["rssi"]
            hw.append(_row("RSSI мін / сер / макс",
                           f"{_c(mn, lvl_rssi(mn))} / {_c(avg, lvl_rssi(avg))} / {_c(mx, lvl_rssi(mx))} dBm"
                           + (f" · SNR мін {_c(h['snr'][0], lvl_snr(h['snr'][0]))} dB" if h.get("snr") else ""), "insights"))
        path = " → ".join(f"<b>{_e(a[1])}</b> ({hhmm(a[0])})" for a in h.get("aps", [])) or "—"
        hw.append(_row("Точки за вікно", path, "route"))
        bad = h.get("roams", 0) >= 3 or h.get("reconnects", 0) or h.get("absent", 0) >= 2
        hw.append(_row("Стабільність",
                       _c(f"роумінгів {h.get('roams', 0)} · перепідключень {h.get('reconnects', 0)} · "
                          f"пропусків {h.get('absent', 0)}", AMBER if bad else GREEN), "sync_problem" if bad else "check_circle"))
        sections.append({"header": f"🕒 Історія {mins} хв ({h['present']}/{h['snapshots']} знімків)", "widgets": hw})
    else:
        sections.append({"header": "🕒 Історія", "widgets": [_para(_c("Ще немає знімків (колектор знімає раз на хвилину).", GREY))]})
    return sections


def _wired_sections(res: dict) -> list[dict]:
    tr = res.get("wired") or {}
    e = tr.get("edge")
    b = tr.get("behind") or {}
    if not e:
        if tr.get("found"):
            txt = "MAC видно лише на транзитних портах: " + ", ".join(f"{_e(p['switch'])} {_e(p['port'])}" for p in tr.get("path", [])[:4])
        else:
            txt = tr.get("error") or "MAC не знайдено в жодній таблиці комутації — пристрій неактивний або за свічем без SNMP."
        return [{"header": "🔌 Кабельне підключення", "widgets": [_para(_c(_e(txt), AMBER))]}]
    conn = []
    if b.get("kind") == "ubiquiti":
        conn.append(_row("За PoE-свічем Ubiquiti", f"<b>{_e(b.get('sysname') or '?')}</b>", "router",
                         "Ubiquiti без SNMP — порт не деталізується"))
    conn.append(_row("Комутатор", f"<b>{_e(e['switch'])}</b> ({_e(e['ip'])})", "router"))
    conn.append(_row("Порт", f"<b>{_e(e['ifname'])}</b>" + (f" «{_e(e['alias'])}»" if e.get("alias") else ""), "settings_ethernet"))
    if e.get("location"):
        conn.append(_row("Місце", _e(e["location"]), "place"))
    if b.get("kind") == "phone":
        conn.append(_row("Через", f"IP-телефон {_e(b.get('sysname'))}", "phone"))
    elif b.get("kind") == "switch":
        conn.append(_row("За портом", _c(f"некерований/невідомий свіч {_e(b.get('sysname') or b.get('sysdesc', '')[:40])}", AMBER), "device_hub"))
    sections = [{"header": "🔌 Кабельне підключення", "widgets": conn}]
    if b.get("kind") != "ubiquiti":
        oper = e.get("oper")
        sp = e.get("speed")
        errs = (e.get("in_err") or 0) + (e.get("out_err") or 0)
        st = [
            _row("Стан порту", _c(f"<b>{_e(oper)}</b>", GREEN if oper == "up" else RED) + f" ({_e(e.get('admin'))})"
                 + f" · змінився {fmt_ago(e.get('changed_ago_s'))} тому", "power"),
            _row("Швидкість", _c(f"<b>{sp} Мбіт/с</b>", GREEN if isinstance(sp, int) and sp >= 1000 else AMBER)
                 if isinstance(sp, int) else "?", "speed"),
            _row("VLAN", _c(f"<b>{_e(e.get('pvid'))}</b>", RED if e.get("pvid") == 500 else GREY)
                 + (" — Unauthenticated" if e.get("pvid") == 500 else ""), "lan"),
            _row("Помилки in / out", _c(f"{_e(e.get('in_err'))} / {_e(e.get('out_err'))}",
                                        RED if errs > 1000 else AMBER if errs > 0 else GREEN), "error_outline"),
        ]
        dx = e.get("dot1x") or {}
        if dx.get("pae"):
            ok = dx.get("port") == "authorized" or dx.get("pae") in ("authenticated", "forceAuth")
            st.append(_row("802.1X", _c(f"<b>{_e(dx.get('pae'))}</b> / {_e(dx.get('port') or '?')}", GREEN if ok else RED),
                           "verified_user" if ok else "gpp_bad"))
        sections.append({"header": "⚙️ Стан порту", "widgets": st})
    return sections


def _nps_section(nps: list[dict] | None, minutes: int) -> dict:
    if nps is None:
        return {"header": "🔐 Авторизація (NPS)", "widgets": [_para(_c("QRadar не відповів вчасно — не перевірено.", GREY))]}
    if not nps:
        return {"header": f"🔐 Авторизація (NPS, {minutes} хв)", "widgets": [_para(_c(
            "Подій немає — автентифікація через NPS не йде (PSK / статичний порт) або пристрій не пробував.", GREY))]}
    ok = [e for e in nps if e["ok"]]
    bad = [e for e in nps if not e["ok"]]
    last = nps[0]
    place = last["called"].split(":")[0] if ":" in last["called"] else last["nas_id"]
    w = [
        _row("Підсумок", _c(f"дозволено {len(ok)}", GREEN) + " · " + _c(f"відмовлено {len(bad)}", RED if bad else GREY), "fact_check"),
        _row(f"Остання подія о {hhmm(last['ts'] // 1000)}",
             _c("<b>✅ доступ дано</b>", GREEN) if last["ok"] else _c("<b>⛔ відмова</b>", RED),
             "verified_user" if last["ok"] else "gpp_bad",
             _e(f"{last['account']} · {last['auth_type']}" + (f"/{last['eap']}" if last.get("eap") and last["eap"] != "-" else "")
                + f" · політика {last['policy']} · через {place} ({last['client']})")),
    ]
    reasons: dict[tuple, int] = {}
    for e in bad:
        k = (e["reason_code"], e["reason"][:160])
        reasons[k] = reasons.get(k, 0) + 1
    for (code, text), n in sorted(reasons.items(), key=lambda x: -x[1])[:3]:
        w.append(_row(f"Причина відмови · Reason {_e(code)} × {n}", _c(_e(text), RED), "report"))
    return {"header": f"🔐 Авторизація (NPS, {minutes} хв)", "widgets": w}


def render_card(res: dict, nps: list[dict] | None, notes: list[str], nps_minutes: int) -> dict:
    """Відповідь бота як cardsV2 + fallbackText (сповіщення/старі клієнти)."""
    medium = res.get("medium")
    kind = {"wifi": "Wi-Fi", "wifi_gone": "Wi-Fi (відключився)", "wired": "кабель",
            "wifi_unknown": "Wi-Fi (не асоціювався)"}.get(medium, "не знайдено")
    header = {"title": f"Діагностика {res.get('ip') or res.get('mac') or ''}",
              "subtitle": (f"MAC {res['mac']} · " if res.get("mac") else "") + kind}
    sections: list[dict] = []
    if not res.get("mac"):
        sections.append({"header": "❓ Пристрій не знайдено", "widgets": [_para(_c(
            "Для цього IP немає ні запису ARP на ядрі (MLNX01/02), ні Wi-Fi-клієнта на WLC — пристрій зараз не в мережі, "
            "IP статичний і неактивний, або це дротовий пристрій у мережі, яку маршрутизує Palo Alto (гостьовий VLAN 500 / "
            "172.18.48.0/21) — ARP фаєрвола бот поки не читає.", AMBER))]})
    elif medium in ("wifi", "wifi_gone"):
        sections += _wifi_sections(res)
    elif medium in ("wired", "wifi_unknown"):
        sections += _wired_sections(res)
    verdict = res.get("verdict") or []
    if verdict:
        sections.append({"header": "🩺 Висновок", "widgets": [_para("<br>".join(_c(_e(v), _verdict_color(v)) for v in verdict))]})
    if res.get("mac"):
        sections.append(_nps_section(nps, nps_minutes))
    if notes:
        sections.append({"widgets": [_para("<br>".join(_c(_e(n), GREY) for n in notes))]})
    fallback = f"Діагностика {res.get('ip') or ''}: {kind}"
    return {"fallbackText": fallback[:200],
            "cardsV2": [{"cardId": "netdiag", "card": {"header": header, "sections": sections}}]}
