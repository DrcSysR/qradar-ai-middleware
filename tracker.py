"""Трекінг пристроїв на вимогу: де пристрій (ноутбук/телефон/сканер) востаннє
реєструвався — на якій точці доступу Wi-Fi або на якому свічі — і де ця точка стоїть
на плані будівлі (карта Zabbix).

Джерело даних — QRadar, а в ньому ЛИШЕ RADIUS-події NPS (XDC02/XDC05): сам WLC як
log source не підключений, тож рівня сигналу (RSSI) немає і відстань у метрах
порахувати нема з чого. Що є в Access-Request (QIDNAME 'IAS_SUCCESS - Accept Request',
IAS ODBC-формат `\\tN=value`):

  5  User-Name            host/lgs53.modern.org | login | MAC без роздільників (MAB)
  6  FQ-User-Name         MODERN\\LGS53$ | MODERN\\login
  7  Called-Station-ID    'CS_109_Eng03:modern' = <AP>:<SSID> (Cisco WLC і Aruba);
                          на дротових свічах — MAC порту свіча
  8  Calling-Station-ID   MAC клієнта 'aa-bb-cc-dd-ee-ff'
  11 NAS-Identifier       ім'я свіча (HPE-6100-38-R010101) або 'Cisco_3504'
  16 Client-Friendly-Name RADIUS-клієнт у NPS: cisco601 / aruba / VLAN600 / switches-v600
  19 NAS-Port-Type        19 = Wireless-802.11, 15 = Ethernet

Тож «місце» = назва точки доступу (або свіча) + час. Карта: у Zabbix є мапи
«Розташування ТД Cisco N-й поверх» (sysmapid 33/34/35) з фоном-планом, на яких точки
стоять як host-елементи з координатами x,y у пікселях фону. Ми беремо їх через Zabbix
API (map.get + host.get + image.get), кешуємо на диск і малюємо на плані коло
радіусом `track_ap_radius_m` (типовий радіус покриття точки) — це і є «приблизна
відстань»: пристрій десь у цьому колі. Масштаб метри/піксель для кожної мапи — у
`track_map_scale_m_per_px`; без нього коло малюється умовним розміром, а радіус у
метрах лише підписується.

Реєстр «пристрій → людина» (`track_registry_file`, JSON, НЕ в git — персональні дані):

  [
    {"person": "Іваненко Іван", "devices": ["LGS53", "a4:5e:60:11:22:33",
                                            {"name": "iPhone", "mac": "d0:03:4b:aa:bb:cc"},
                                            {"name": "Ноутбук", "host": "LGS53", "mac": ["…", "…"]}]},
    ...
  ]

Пристрій-рядок — ім'я хоста або MAC. Пристрій-об'єкт: `name` — підпис для людини,
`host` — доменне ім'я (за ним шукаються host/NAME і NAME$), `mac`/`macs` — один або
список. Якщо `host` не задано, `name` береться за ім'я хоста лише коли в ньому немає
пробілів (інакше «Телефон Олени» перетворився б на пошук хоста з таким іменем).

Запит приймає рядки будь-якого виду: ім'я хоста, MAC (будь-який роздільник), логін або
прізвище з реєстру (тоді беруться всі пристрої цієї людини).

Друга лінза — DHCP (`LinuxDHCP @ dhcp1`, ISC dhcpd: `DHCPACK on <ip> to <mac> (<hostname>) via
<relay>`). Потрібна для пристроїв, яких у RADIUS немає взагалі: SSID `me_mobile` — PSK без
NPS, а телефони ще й рандомізують MAC. Тоді єдиний стабільний ідентифікатор — hostname у
DHCP-запиті (`dhcp_host` у реєстрі, напр. "F6"): з нього дістаємо поточний випадковий MAC,
IP і relay (= VLAN/підмережа), а знайдені MAC ще раз проганяємо через RADIUS. Точку доступу
для PSK-клієнта QRadar не знає — її знає лише WLC (див. docs/changes/2026-11-02-b).

Третя лінза — живі оренди DHCP-сервера Palo Alto (`fetch_pa_dhcp`, XML API type=op): гостьовий
VLAN 500 з hostname-ами телефонів і VLAN точок доступу; це стан «зараз», не історія.

Місце точки без мапи — інвентар Zabbix (`fetch_inventory`: location_lat/lon, site_rack,
location) і файл будівель `track_buildings_file`: GPS крайніх точок кожної будівлі + пікселі
тих самих кутів на кожному плані поверху. З цього виходить масштаб м/px і GPS для будь-якої
точки плану, а інвентарна точка з GPS кладеться на план своєї будівлі/поверху (формат — біля
`fit_georef`). Порядок джерел у `with_location`: елемент мапи → GPS інвентарю через прив'язку →
лише текст інвентарю + посилання на карту.
"""

import base64
import json
import logging
import math
import os
import re
import time

import httpx

FIELD = re.compile(r"\t(\d+)=([^\t]*)")
HEX12 = re.compile(r"^[0-9a-f]{12}$")
BASE_DIR = "/opt/qradar-middleware"
CACHE_DIR = os.path.join(BASE_DIR, "cache")


# ----------------------------------------------------------------------------- ідентифікатори
def norm_mac(s: str) -> str | None:
    """'A4:5E:60:11:22:33' / 'a4-5e-...' / 'a45e60112233' → 'a45e60112233'; інакше None."""
    if not s:
        return None
    h = re.sub(r"[^0-9a-fA-F]", "", s).lower()
    return h if HEX12.match(h) else None


def mac_dashed(h: str) -> str:
    return "-".join(h[i:i + 2] for i in range(0, 12, 2))


def norm_name(s: str) -> str:
    """host/lgs53.modern.org → lgs53; MODERN\\LGS53$ → lgs53; ivan.petrenko → ivan.petrenko."""
    s = (s or "").strip()
    s = s.split("\\")[-1]
    if s.lower().startswith("host/"):
        s = s[5:]
    s = s.split("@")[0].split(".modern.org")[0].rstrip("$")
    return s.lower()


# ----------------------------------------------------------------------------- реєстр
def load_registry(path: str) -> list[dict]:
    """Нормалізований список: [{person, name, macs:[hex12], label}]. Порожній, якщо файлу нема."""
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        logging.warning(f"track: реєстр {path} не читається: {e}")
        return []
    out = []
    for person in data if isinstance(data, list) else []:
        who = str(person.get("person", "")).strip()
        for d in person.get("devices", []):
            if isinstance(d, str):
                mac = norm_mac(d)
                out.append({"person": who, "name": None if mac else norm_name(d), "macs": [mac] if mac else [],
                            "dhcp_host": "" if mac else d.strip(), "label": d})
            elif isinstance(d, dict):
                macs = d.get("mac") or d.get("macs") or []
                macs = [macs] if isinstance(macs, str) else list(macs)
                macs = [m for m in (norm_mac(x) for x in macs) if m]
                name = d.get("name") or ""
                host = d.get("host") or (name if name and not re.search(r"\s", name) else "")
                dhcp_host = d.get("dhcp_host") or host or ""
                out.append({"person": who, "name": norm_name(host) if host else None, "macs": macs,
                            "dhcp_host": dhcp_host.strip(), "label": name or host or (mac_dashed(macs[0]) if macs else "?")})
    return out


def resolve_targets(items: list[str], registry: list[dict]) -> list[dict]:
    """Рядки запиту → цілі пошуку. Ціль: {query, label, person, name, macs}."""
    targets, seen = [], set()

    def add(t):
        key = (t.get("name"), tuple(sorted(t.get("macs", []))))
        if key in seen:
            return
        seen.add(key)
        targets.append(t)

    for raw in items:
        q = (raw or "").strip()
        if not q:
            continue
        mac = norm_mac(q)
        if mac:
            hit = next((r for r in registry if mac in r["macs"]), None)
            add({"query": q, "label": hit["label"] if hit else mac_dashed(mac), "person": hit["person"] if hit else "",
                 "name": hit["name"] if hit else None, "macs": [mac], "dhcp_host": hit.get("dhcp_host", "") if hit else ""})
            continue
        ql = q.lower()
        # прізвище / частина імені людини з реєстру → усі її пристрої
        people = [r for r in registry if r["person"] and ql in r["person"].lower()]
        if people:
            for r in people:
                add({"query": q, "label": r["label"], "person": r["person"], "name": r["name"], "macs": list(r["macs"]),
                     "dhcp_host": r.get("dhcp_host", "")})
            continue
        name = norm_name(q)
        hit = next((r for r in registry if r["name"] == name), None)
        add({"query": q, "label": hit["label"] if hit else q, "person": hit["person"] if hit else "",
             "name": name, "macs": list(hit["macs"]) if hit else [], "dhcp_host": hit.get("dhcp_host", "") if hit else q})
    return targets


# ----------------------------------------------------------------------------- QRadar
def _lit(s: str) -> str:
    return s.replace("'", "''")


def build_aql(targets: list[dict], hours: float, limit: int) -> str:
    """Один пошук на всі цілі. Зворотний слеш в ILIKE — літерал (перевірено 02.11.2026:
    '%\\INS04$\\t%' матчить, '%\\\\INS04$\\t%' — ні), тому для FQ-імені шаблон '%\\NAME$<tab>%'.
    Табуляція всередині літерала — справжній символ TAB: поля IAS розділені саме ним,
    і це відсікає збіги по підрядку (lgs5 ≠ lgs53)."""
    conds = []
    for t in targets:
        for m in t["macs"]:
            conds.append(f"UTF8(payload) ILIKE '%\t8={mac_dashed(m)}\t%'")   # Wi-Fi/дріт, 802.1X і MAB
            conds.append(f"UTF8(payload) ILIKE '%\t5={m}\t%'")               # MAB: User-Name = MAC
        if t["name"]:
            n = _lit(t["name"])
            conds.append(f"UTF8(payload) ILIKE '%=host/{n}.%'")             # машинний акаунт
            conds.append(f"UTF8(payload) ILIKE '%\\{n}$\t%'")                # MODERN\NAME$
            conds.append(f"UTF8(payload) ILIKE '%\\{n}\t%'")                 # MODERN\login (user-auth)
            conds.append(f"UTF8(payload) ILIKE '%\t5={n}@%'")                # login@domain
    if not conds:
        return ""
    return ("SELECT starttime AS ts, UTF8(payload) AS p FROM events "
            "WHERE LOGSOURCENAME(logsourceid) ILIKE '%NPS%' "
            "AND QIDNAME(qid) = 'IAS_SUCCESS - Accept Request' "
            f"AND ({' OR '.join(conds)}) "
            f"ORDER BY starttime DESC LIMIT {int(limit)} LAST {max(1, int(hours))} HOURS")


async def run_aql(client: httpx.AsyncClient, api_url: str, headers: dict, aql: str, timeout_s: float) -> list[dict] | None:
    """POST /ariel/searches (form-тіло) → полінг з дедлайном → results → DELETE. None = не вдалось."""
    form_headers = {**headers, "Content-Type": "application/x-www-form-urlencoded"}
    r = await client.post(f"{api_url}/ariel/searches", headers=form_headers, data={"query_expression": aql})
    if r.status_code not in (200, 201):
        logging.error(f"track: AQL HTTP {r.status_code}: {r.text[:200]}")
        return None
    sid = r.json().get("search_id")
    deadline = time.monotonic() + timeout_s
    try:
        while True:
            if time.monotonic() > deadline:
                logging.error(f"track: AQL {sid} не завершився за {timeout_s:.0f} с")
                return None
            s = await client.get(f"{api_url}/ariel/searches/{sid}", headers=headers)
            st = s.json().get("status", "ERROR") if s.status_code == 200 else "ERROR"
            if st == "COMPLETED":
                break
            if st in ("ERROR", "CANCELED"):
                logging.error(f"track: AQL {sid} status={st}")
                return None
            import asyncio
            await asyncio.sleep(2)
        res = await client.get(f"{api_url}/ariel/searches/{sid}/results", headers=headers)
        return res.json().get("events", []) if res.status_code == 200 else None
    finally:
        try:
            await client.delete(f"{api_url}/ariel/searches/{sid}", headers=headers)
        except Exception:
            pass


def parse_sighting(ev: dict) -> dict | None:
    f = dict(FIELD.findall(ev.get("p", "")))
    user = f.get("5") or f.get("6") or ""
    mac = norm_mac(f.get("8", ""))
    csi = f.get("7", "")
    wifi = f.get("19") == "19" or ":" in csi
    ap, ssid = (csi.split(":", 1) + [""])[:2] if ":" in csi else ("", "")
    return {
        "ts": int(ev.get("ts") or 0),
        "user": user,
        "user_norm": norm_name(user) if not HEX12.match(user.lower()) else "",
        "mac": mac,
        "medium": "wifi" if wifi else "wired",
        "ap": ap,
        "ssid": ssid,
        "switch": "" if wifi else (f.get("11") or f.get("16") or ""),
        "port_mac": "" if wifi else csi,
        "nas": f.get("16", ""),
        "ok": f.get("25", "0") in ("0", ""),
    }


def assign(targets: list[dict], events: list[dict]) -> None:
    """Розкласти події по цілях (за MAC або нормалізованим іменем) і вирахувати
    last / last_wifi / last_wired / список точок за вікно. Мутує targets."""
    for t in targets:
        t.update({"sightings": 0, "last": None, "last_wifi": None, "last_wired": None, "aps": {}, "macs_seen": set()})
    for ev in events:
        s = parse_sighting(ev)
        if not s:
            continue
        for t in targets:
            hit = (s["mac"] and s["mac"] in t["macs"]) or (t["name"] and s["user_norm"] == t["name"])
            if not hit:
                continue
            t["sightings"] += 1
            if s["mac"]:
                t["macs_seen"].add(s["mac"])
            if t["last"] is None or s["ts"] > t["last"]["ts"]:
                t["last"] = s
            k = "last_wifi" if s["medium"] == "wifi" else "last_wired"
            if t[k] is None or s["ts"] > t[k]["ts"]:
                t[k] = s
            place = s["ap"] or s["switch"]
            if place:
                a = t["aps"].setdefault(place, {"count": 0, "first": s["ts"], "last": s["ts"], "medium": s["medium"]})
                a["count"] += 1
                a["first"] = min(a["first"], s["ts"])
                a["last"] = max(a["last"], s["ts"])
    for t in targets:
        t["macs_seen"] = sorted(mac_dashed(m) for m in t["macs_seen"])
        t["aps"] = sorted(({"place": k, **v} for k, v in t["aps"].items()), key=lambda x: -x["last"])


# ----------------------------------------------------------------------------- DHCP
DHCP_RE = re.compile(r"DHCPACK on ([\d.]+) to ([0-9a-f:]{17})(?: \(([^)]*)\))? via ([\d.]+|\w+)", re.I)


def build_dhcp_aql(targets: list[dict], hours: float, limit: int, logsource: str) -> str:
    """DHCPACK по hostname у дужках (стабільний для рандомізованого MAC) і по відомих MAC."""
    conds = []
    for t in targets:
        if t.get("dhcp_host"):
            conds.append(f"UTF8(payload) ILIKE '%({_lit(t['dhcp_host'])})%'")
        for m in t["macs"]:
            conds.append(f"UTF8(payload) ILIKE '% {':'.join(m[i:i + 2] for i in range(0, 12, 2))} %'")
    if not conds:
        return ""
    return ("SELECT starttime AS ts, UTF8(payload) AS p FROM events "
            f"WHERE LOGSOURCENAME(logsourceid) ILIKE '{_lit(logsource)}' AND QIDNAME(qid) = 'DHCPACK' "
            f"AND ({' OR '.join(conds)}) ORDER BY starttime DESC LIMIT {int(limit)} LAST {max(1, int(hours))} HOURS")


def assign_dhcp(targets: list[dict], events: list[dict]) -> list[str]:
    """Розкладає DHCPACK по цілях (за hostname або MAC), ставить last_dhcp і dhcp_macs.
    Повертає нові MAC (не з реєстру), які варто доганяти через RADIUS."""
    new_macs = []
    for t in targets:
        t.setdefault("last_dhcp", None)
        t.setdefault("dhcp_macs", {})
    for ev in events:
        m = DHCP_RE.search(ev.get("p", ""))
        if not m:
            continue
        ip, mac, host, relay = m.group(1), norm_mac(m.group(2)), (m.group(3) or "").strip(), m.group(4)
        ts = int(ev.get("ts") or 0)
        for t in targets:
            hit = (mac and mac in t["macs"]) or (t.get("dhcp_host") and host.lower() == t["dhcp_host"].lower())
            if not hit:
                continue
            rec = {"ts": ts, "ip": ip, "mac": mac, "host": host, "relay": relay}
            if t["last_dhcp"] is None or ts > t["last_dhcp"]["ts"]:
                t["last_dhcp"] = rec
            d = t["dhcp_macs"].setdefault(mac, {"first": ts, "last": ts, "ips": set()})
            d["first"], d["last"] = min(d["first"], ts), max(d["last"], ts)
            d["ips"].add(ip)
            if mac not in t["macs"] and mac not in new_macs:
                new_macs.append(mac)
    for t in targets:
        t["dhcp_macs"] = sorted(({"mac": mac_dashed(k), "first": v["first"], "last": v["last"], "ips": sorted(v["ips"])}
                                 for k, v in t["dhcp_macs"].items()), key=lambda x: -x["last"])
    return new_macs


# ----------------------------------------------------------------------------- Palo Alto DHCP (живий стан)
async def fetch_pa_dhcp(client: httpx.AsyncClient, cfg: dict) -> tuple[list[dict], str]:
    """Таблиця оренд DHCP-сервера pa-vm — ЖИВИЙ стан, не історія (у QRadar цих подій немає:
    переміряно 03.11.2026, PaSeries за 7 діб не містить 'dhcp'). PA роздає адреси гостьовому
    VLAN 500 (172.18.48/21: телефони з hostname-ами), AP-VLAN 605 (172.17.65.x: самі точки
    `CS-…`), .10 і .12. XML API `type=op`, `show dhcp server lease interface all`.
    Ключ `pa_api_key` має бути від окремого адміна з роллю «XML API: Operational Requests»
    (read-only) — НЕ superuser і НЕ user-id-ключ QRadar (у того op → 403)."""
    host, key = cfg.get("pa_api_host", ""), cfg.get("pa_api_key", "")
    if not (host and key) or not cfg.get("track_pa_dhcp_enabled", True):
        return [], "pa_api_host / pa_api_key не задані"
    try:
        r = await client.get(f"https://{host}/api/", params={
            "type": "op", "cmd": "<show><dhcp><server><lease><interface>all</interface></lease></server></dhcp></show>"},
            headers={"X-PAN-KEY": key}, timeout=25.0)
        return parse_pa_dhcp(r.text)
    except Exception as e:
        logging.warning(f"track: PA DHCP недоступний: {e}")
        return [], str(e)


def parse_pa_dhcp(xml_text: str) -> tuple[list[dict], str]:
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return [], f"PA: не XML ({e})"
    if root.get("status") != "success":
        msg = root.findtext(".//msg") or root.findtext(".//line") or xml_text[:120]
        return [], f"PA API: {msg.strip()}"
    out = []
    for iface in root.iter("interface"):
        for e in iface.iter("entry"):
            f = {c.tag: (c.text or "").strip() for c in e}
            if not f.get("ip"):
                continue
            out.append({"iface": iface.get("name", ""), "ip": f["ip"], "mac": norm_mac(f.get("mac", "")) or "",
                        "hostname": f.get("hostname", ""), "state": f.get("state", ""), "lease_time": f.get("leasetime", "")})
    return out, ""


def assign_pa_dhcp(targets: list[dict], leases: list[dict]) -> list[str]:
    """Збіг за hostname (dhcp_host) або MAC → t['pa_dhcp'] = список поточних оренд.
    Повертає нові MAC для дорахунку через RADIUS."""
    new_macs = []
    for t in targets:
        t["pa_dhcp"] = []
        for L in leases:
            hit = (L["mac"] and L["mac"] in t["macs"]) or (t.get("dhcp_host") and L["hostname"].lower() == t["dhcp_host"].lower())
            if hit:
                t["pa_dhcp"].append({**L, "mac": mac_dashed(L["mac"]) if L["mac"] else ""})
                if L["mac"] and L["mac"] not in t["macs"] and L["mac"] not in new_macs:
                    new_macs.append(L["mac"])
    return new_macs


# ----------------------------------------------------------------------------- Zabbix: карта точок
def _cache_path(name: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, name)


def zabbix_token(cfg: dict) -> str:
    """Токен API Zabbix: ключ zabbix_api_token у config.json, інакше вміст окремого файлу
    zabbix_api_token_file (600 root:qmiddleware, поза git — секрет лежить окремо від конфігу)."""
    tok = (cfg.get("zabbix_api_token") or "").strip()
    if tok:
        return tok
    path = cfg.get("zabbix_api_token_file") or os.path.join(BASE_DIR, "zabbix_api_token")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


async def _zbx(client: httpx.AsyncClient, url: str, token: str, method: str, params: dict):
    r = await client.post(url.rstrip("/") + "/api_jsonrpc.php",
                          headers={"Content-Type": "application/json-rpc", "Authorization": f"Bearer {token}"},
                          json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
    r.raise_for_status()
    body = r.json()
    if "error" in body:
        raise RuntimeError(f"Zabbix {method}: {body['error'].get('data') or body['error'].get('message')}")
    return body["result"]


async def fetch_ap_map(client: httpx.AsyncClient, cfg: dict, force: bool = False) -> dict:
    """Індекс точок: {fetched_at, maps:{id:{name,w,h,image}}, aps:{APNAME_UPPER:{map,x,y,label,host}},
    labels:{LABEL_UPPER:[...]}}. Кеш cache/ap_map.json на track_map_cache_hours; фони —
    cache/map_<id>.png. Без zabbix_url/zabbix_api_token повертає порожній індекс (локація
    недоступна, але точка з NPS усе одно показується)."""
    path = _cache_path("ap_map.json")
    ttl = float(cfg.get("track_map_cache_hours", 24)) * 3600
    if not force and os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl:
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            pass
    url, token = cfg.get("zabbix_url", ""), zabbix_token(cfg)
    map_ids = [str(x) for x in cfg.get("track_zabbix_maps", [])]
    idx = {"fetched_at": int(time.time()), "maps": {}, "aps": {}, "labels": {}, "inventory": {}, "error": ""}
    if not (url and token and map_ids):
        idx["error"] = "zabbix_url / zabbix_api_token (або файл zabbix_api_token_file) / track_zabbix_maps не задані"
        return idx
    try:
        maps = await _zbx(client, url, token, "map.get",
                          {"sysmapids": map_ids, "output": ["sysmapid", "name", "width", "height", "backgroundid"],
                           "selectSelements": ["selementid", "elementtype", "elements", "label", "x", "y"]})
        host_ids = sorted({e["elements"][0]["hostid"] for m in maps for e in m.get("selements", [])
                           if str(e.get("elementtype")) == "0" and e.get("elements")})
        hosts = {}
        if host_ids:
            for h in await _zbx(client, url, token, "host.get", {"hostids": host_ids, "output": ["hostid", "host", "name"]}):
                hosts[h["hostid"]] = h
        for m in maps:
            mid = str(m["sysmapid"])
            img = ""
            bg = m.get("backgroundid")
            if bg and str(bg) != "0":
                try:
                    imgs = await _zbx(client, url, token, "image.get", {"imageids": [bg], "select_image": True, "output": ["imageid"]})
                    if imgs and imgs[0].get("image"):
                        with open(_cache_path(f"map_{mid}.png"), "wb") as fh:
                            fh.write(base64.b64decode(imgs[0]["image"]))
                        img = f"/track/map/{mid}"
                except Exception as e:
                    logging.warning(f"track: фон мапи {mid} не завантажено: {e}")
            idx["maps"][mid] = {"name": m["name"], "w": int(m["width"]), "h": int(m["height"]), "image": img}
            for e in m.get("selements", []):
                label = (e.get("label") or "").strip().split("\n")[0]
                host = ""
                if str(e.get("elementtype")) == "0" and e.get("elements"):
                    host = hosts.get(e["elements"][0]["hostid"], {}).get("host", "")
                rec = {"map": mid, "x": int(e["x"]), "y": int(e["y"]), "label": label, "host": host}
                if host:
                    idx["aps"][host.upper()] = rec
                if label:
                    idx["labels"].setdefault(label.upper(), []).append(rec)
        # Інвентар хостів (Zabbix Inventory, ручний або авто): друге джерело місця, незалежне
        # від мап — GPS (location_lat/lon) + «будівля/поверх» (site_rack/location). Станом на
        # 2026-11-03 заповнений лише у CS_IT_01; читаємо все, що є, помилка тут не валить індекс.
        if cfg.get("track_zabbix_inventory", True):
            try:
                idx["inventory"] = await fetch_inventory(client, url, token)
            except Exception as e:
                logging.warning(f"track: інвентар Zabbix не прочитано: {e}")
    except Exception as e:
        logging.error(f"track: Zabbix недоступний: {e}")
        idx["error"] = str(e)
        if os.path.exists(path):  # старий кеш кращий за нічого
            try:
                with open(path, encoding="utf-8") as fh:
                    old = json.load(fh)
                old["error"] = f"Zabbix недоступний ({e}); показано кеш від {time.strftime('%Y-%m-%d %H:%M', time.localtime(old.get('fetched_at', 0)))}"
                return old
            except (OSError, ValueError):
                pass
        return idx
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(idx, fh, ensure_ascii=False)
    return idx


INV_FIELDS = ["location", "location_lat", "location_lon", "site_rack", "site_city", "site_address_a",
              "model", "serialno_a", "url_a"]


async def fetch_inventory(client: httpx.AsyncClient, url: str, token: str) -> dict:
    """{HOST_UPPER: {host, name, lat, lon, location, site_rack, site_city, site_address, model,
    serial, ip}} — лише хости, у яких заповнено хоч щось із місця (GPS / location / site_rack);
    інші поля інвентарю тягнуться для довідки."""
    hosts = await _zbx(client, url, token, "host.get",
                       {"output": ["hostid", "host", "name"], "withInventory": True, "selectInventory": INV_FIELDS})
    out = {}
    for h in hosts:
        inv = h.get("inventory") or {}
        if not isinstance(inv, dict):
            continue
        lat, lon = _num(inv.get("location_lat")), _num(inv.get("location_lon"))
        rec = {"host": h.get("host", ""), "name": h.get("name", ""),
               "lat": lat, "lon": lon,
               "location": (inv.get("location") or "").strip(),
               "site_rack": (inv.get("site_rack") or "").strip(),
               "site_city": (inv.get("site_city") or "").strip(),
               "site_address": (inv.get("site_address_a") or "").strip(),
               "model": (inv.get("model") or "").strip(),
               "serial": (inv.get("serialno_a") or "").strip(),
               "ip": (inv.get("url_a") or "").strip()}
        if (lat is not None and lon is not None) or rec["location"] or rec["site_rack"]:
            out[rec["host"].upper()] = rec
    return out


def _num(v) -> float | None:
    try:
        return float(str(v).strip()) if v not in (None, "") else None
    except ValueError:
        return None


# ---------- будівлі та гео-прив'язка планів: «кути будівлі ↔ пікселі на мапі» ----------
# Файл track_buildings_file (JSON поза git; будівель може бути кілька):
#   [{"name": "Корпус 1, Струмівка",
#     "inventory_match": ["build 1"],                    # підрядки site_rack/location в інвентарі Zabbix
#     "corners": {"NE": [50.7445, 25.3962], "SE": [...], "SW": [...], "NW": [...]},   # GPS крайніх точок
#     "floors": [{"map": 33, "floor": "floor 2",         # мапа Zabbix і підрядок поверху для інвентарю
#                 "px": {"NE": [3368, 127], "SE": [3368, 655], "SW": [78, 655], "NW": [164, 127]}}]}]
# Кути задаються один раз на будівлю; на кожному плані поверху вказуються пікселі тих самих
# кутів (≥2 на мапу). Підгонка подібності (масштаб + поворот + зсув) методом найменших квадратів
# у комплексній формі: z = x − i·y (вісь y плану вниз), w = east + i·north у метрах від
# центроїда, w = c·z + d. |c| = метрів на піксель — замінює ручний track_map_scale_m_per_px.
M_PER_DEG_LAT = 111_320.0


def fit_georef(points: list[dict]) -> dict | None:
    """points: [{"px": [x, y], "gps": [lat, lon]}, …] (≥2) → параметри перетворення або None."""
    z, lat, lon = [], [], []
    for p in points:
        try:
            z.append(complex(float(p["px"][0]), -float(p["px"][1])))
            lat.append(float(p["gps"][0])); lon.append(float(p["gps"][1]))
        except (KeyError, TypeError, ValueError, IndexError):
            return None
    if len(z) < 2:
        return None
    lat0, lon0 = sum(lat) / len(lat), sum(lon) / len(lon)
    kx = M_PER_DEG_LAT * math.cos(math.radians(lat0))
    w = [complex((lo - lon0) * kx, (la - lat0) * M_PER_DEG_LAT) for la, lo in zip(lat, lon)]
    zm, wm = sum(z) / len(z), sum(w) / len(w)
    den = sum(abs(zi - zm) ** 2 for zi in z)
    if den == 0:
        return None
    c = sum((zi - zm).conjugate() * (wi - wm) for zi, wi in zip(z, w)) / den
    if abs(c) == 0:
        return None
    d = wm - c * zm
    rms = math.sqrt(sum(abs(c * zi + d - wi) ** 2 for zi, wi in zip(z, w)) / len(z))
    return {"lat0": lat0, "lon0": lon0, "kx": kx, "c": c, "d": d, "m_per_px": abs(c),
            "rot_deg": math.degrees(math.atan2(c.imag, c.real)), "rms_m": rms, "points": len(z)}


def px_to_gps(g: dict, x: float, y: float) -> tuple[float, float]:
    w = g["c"] * complex(x, -y) + g["d"]
    return g["lat0"] + w.imag / M_PER_DEG_LAT, g["lon0"] + w.real / g["kx"]


def gps_to_px(g: dict, lat: float, lon: float) -> tuple[float, float]:
    w = complex((lon - g["lon0"]) * g["kx"], (lat - g["lat0"]) * M_PER_DEG_LAT)
    z = (w - g["d"]) / g["c"]
    return z.real, -z.imag


def in_polygon(lat: float, lon: float, poly: list[list[float]]) -> bool:
    """Точка всередині многокутника з GPS-вершин (парність перетинів променя)."""
    inside = False
    n = len(poly)
    for i in range(n):
        (y1, x1), (y2, x2) = poly[i], poly[(i + 1) % n]
        if (y1 > lat) != (y2 > lat):
            xi = x1 + (lat - y1) * (x2 - x1) / (y2 - y1)
            if lon < xi:
                inside = not inside
    return inside


def load_buildings(path: str) -> list[dict]:
    """Опис будівель із файлу; криві записи пропускаються з логом, без файлу — []."""
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        logging.warning(f"track: {path}: {e}")
        return []
    out = []
    for b in data if isinstance(data, list) else []:
        corners = b.get("corners") if isinstance(b, dict) else None
        if not isinstance(corners, dict) or len(corners) < 2:
            logging.warning(f"track: будівля {b.get('name') if isinstance(b, dict) else b!r}: потрібно ≥2 кути в corners")
            continue
        floors = []
        for f in b.get("floors") or []:
            pts = [{"px": px, "gps": corners[k]} for k, px in (f.get("px") or {}).items() if k in corners]
            g = fit_georef(pts)
            if not g:
                logging.warning(f"track: будівля {b.get('name')}, мапа {f.get('map')}: потрібно ≥2 кути з px, що є в corners")
                continue
            g["floor"] = (f.get("floor") or "").strip().lower()
            g["map"] = str(f.get("map"))
            floors.append(g)
        out.append({"name": b.get("name") or "", "corners": corners,
                    "inventory_match": [str(s).lower() for s in (b.get("inventory_match") or [])],
                    "floors": floors})
    return out


def load_georefs(cfg: dict) -> dict:
    """{map_id: georef(+building, floor, inventory_match)} з усіх будівель track_buildings_file."""
    out = {}
    for b in load_buildings(cfg.get("track_buildings_file") or ""):
        for g in b["floors"]:
            out[g["map"]] = {**g, "building": b["name"], "inventory_match": b["inventory_match"],
                             "corners": list(b["corners"].values())}
    return out


def building_of(lat: float, lon: float, cfg: dict) -> str:
    """Назва будівлі, у контур якої потрапляє GPS-точка (інвентар без мапи), або ''."""
    for b in load_buildings(cfg.get("track_buildings_file") or ""):
        if len(b["corners"]) >= 3 and in_polygon(lat, lon, list(b["corners"].values())):
            return b["name"]
    return ""


def locate_ap(ap_name: str, idx: dict) -> dict | None:
    """Точка з RADIUS ('CS_109_Eng03') → елемент мапи. Спершу host-елемент з тим самим
    ім'ям, потім підпис мапи, що збігається з початком імені ('CS_109'): на мапах точки
    підписані коротко."""
    if not ap_name:
        return None
    key = ap_name.upper()
    rec = idx.get("aps", {}).get(key)
    if rec:
        return rec
    best = None
    for label, recs in idx.get("labels", {}).items():
        if label and key.startswith(label) and (best is None or len(label) > len(best[0])):
            best = (label, recs[0])
    return best[1] if best else None


def with_location(t: dict, idx: dict, cfg: dict, georefs: dict | None = None) -> dict:
    """Додає до цілі блок location за останньою Wi-Fi-точкою (або None).

    Порядок джерел: (1) елемент мапи Zabbix (source="map"; з гео-прив'язкою — ще й GPS точки);
    (2) GPS з інвентарю Zabbix, покладений на план через прив'язку тієї мапи, чий "floor"
    збігається з site_rack/location (source="inventory"); (3) лише інвентар — текст
    «будівля/поверх» + посилання на карту, без плану. Радіус у пікселях: ручний
    track_map_scale_m_per_px, інакше масштаб із прив'язки."""
    s = t.get("last_wifi")
    t["location"] = None
    if not s or not s.get("ap"):
        return t
    ap = s["ap"]
    georefs = georefs if georefs is not None else load_georefs(cfg)
    loc = {"ap": ap, "known": False, "source": None}
    inv = idx.get("inventory", {}).get(ap.upper())
    if inv:
        loc["inventory"] = inv
    radius_m = float(cfg.get("track_ap_radius_m", 20))
    rec = locate_ap(ap, idx)
    g = None
    if rec:
        m = idx["maps"].get(rec["map"], {})
        g = georefs.get(rec["map"])
        loc.update({"known": True, "source": "map", "map": rec["map"], "map_name": m.get("name", ""),
                    "x": rec["x"], "y": rec["y"], "w": m.get("w"), "h": m.get("h"), "image": m.get("image", "")})
        if g:
            lat, lon = px_to_gps(g, rec["x"] + 24, rec["y"] + 24)
            loc["gps"] = [round(lat, 6), round(lon, 6)]
    elif inv and inv.get("lat") is not None and inv.get("lon") is not None:
        # Мапа для інвентарної точки: будівля — за inventory_match АБО за тим, що GPS лежить у її
        # контурі; поверх — за підрядком floor у site_rack/location. Обидва мають збігтися.
        where = f"{inv.get('site_rack', '')} {inv.get('location', '')}".lower()
        for mid, gg in georefs.items():
            m = idx.get("maps", {}).get(mid)
            if not m or not gg.get("floor") or gg["floor"] not in where:
                continue
            b_ok = any(s and s in where for s in gg.get("inventory_match", [])) or \
                   (len(gg.get("corners", [])) >= 3 and in_polygon(inv["lat"], inv["lon"], gg["corners"]))
            if not b_ok:
                continue
            x, y = gps_to_px(gg, inv["lat"], inv["lon"])
            if 0 <= x <= m.get("w", 0) and 0 <= y <= m.get("h", 0):
                g = gg
                # x,y у термінах елемента мапи (лівий верх іконки 48px) — як і в rec, сторінка додає +24
                loc.update({"known": True, "source": "inventory", "map": mid, "map_name": m.get("name", ""),
                            "x": int(round(x)) - 24, "y": int(round(y)) - 24, "w": m.get("w"), "h": m.get("h"),
                            "image": m.get("image", "")})
                break
    if "gps" not in loc and inv and inv.get("lat") is not None and inv.get("lon") is not None:
        loc["gps"] = [inv["lat"], inv["lon"]]
    if loc.get("gps"):
        loc["gps_url"] = f"https://www.google.com/maps?q={loc['gps'][0]},{loc['gps'][1]}"
        loc["building"] = (g or {}).get("building") or building_of(loc["gps"][0], loc["gps"][1], cfg)
    if loc["known"]:
        scale = (cfg.get("track_map_scale_m_per_px") or {}).get(loc["map"])
        if scale:
            loc["scale_source"] = "config"
        elif g:
            scale = g["m_per_px"]
            loc["scale_source"] = f"georef ({g['points']} т., похибка {g['rms_m']:.1f} м)"
        loc["radius_m"] = radius_m
        loc["radius_px"] = (radius_m / float(scale)) if scale else None
    t["location"] = loc
    return t


def ts_str(ms: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000)) if ms else ""


def to_public(t: dict) -> dict:
    """Серіалізація цілі для JSON/HTML (часи у рядках, без службових полів)."""
    def sig(s):
        return None if not s else {**s, "time": ts_str(s["ts"])}
    return {
        "query": t["query"], "label": t["label"], "person": t["person"], "name": t["name"],
        "macs": [mac_dashed(m) for m in t["macs"]], "macs_seen": t.get("macs_seen", []),
        "sightings": t.get("sightings", 0),
        "last": sig(t.get("last")), "last_wifi": sig(t.get("last_wifi")), "last_wired": sig(t.get("last_wired")),
        "places": [{**a, "first_time": ts_str(a["first"]), "last_time": ts_str(a["last"])} for a in t.get("aps", [])],
        "last_dhcp": ({**t["last_dhcp"], "mac": mac_dashed(t["last_dhcp"]["mac"]) if t["last_dhcp"].get("mac") else "",
                       "time": ts_str(t["last_dhcp"]["ts"])} if t.get("last_dhcp") else None),
        "dhcp_macs": [{**d, "first_time": ts_str(d["first"]), "last_time": ts_str(d["last"])} for d in t.get("dhcp_macs", [])],
        "pa_dhcp": t.get("pa_dhcp", []),
        "location": t.get("location"),
    }
