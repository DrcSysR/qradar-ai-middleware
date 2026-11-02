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
"""

import base64
import json
import logging
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
                out.append({"person": who, "name": None if mac else norm_name(d), "macs": [mac] if mac else [], "label": d})
            elif isinstance(d, dict):
                macs = d.get("mac") or d.get("macs") or []
                macs = [macs] if isinstance(macs, str) else list(macs)
                macs = [m for m in (norm_mac(x) for x in macs) if m]
                name = d.get("name") or ""
                host = d.get("host") or (name if name and not re.search(r"\s", name) else "")
                out.append({"person": who, "name": norm_name(host) if host else None, "macs": macs,
                            "label": name or host or (mac_dashed(macs[0]) if macs else "?")})
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
                 "name": hit["name"] if hit else None, "macs": [mac]})
            continue
        ql = q.lower()
        # прізвище / частина імені людини з реєстру → усі її пристрої
        people = [r for r in registry if r["person"] and ql in r["person"].lower()]
        if people:
            for r in people:
                add({"query": q, "label": r["label"], "person": r["person"], "name": r["name"], "macs": list(r["macs"])})
            continue
        name = norm_name(q)
        hit = next((r for r in registry if r["name"] == name), None)
        add({"query": q, "label": hit["label"] if hit else q, "person": hit["person"] if hit else "",
             "name": name, "macs": list(hit["macs"]) if hit else []})
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


# ----------------------------------------------------------------------------- Zabbix: карта точок
def _cache_path(name: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, name)


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
    url, token = cfg.get("zabbix_url", ""), cfg.get("zabbix_api_token", "")
    map_ids = [str(x) for x in cfg.get("track_zabbix_maps", [])]
    idx = {"fetched_at": int(time.time()), "maps": {}, "aps": {}, "labels": {}, "error": ""}
    if not (url and token and map_ids):
        idx["error"] = "zabbix_url / zabbix_api_token / track_zabbix_maps не задані"
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


def with_location(t: dict, idx: dict, cfg: dict) -> dict:
    """Додає до цілі блок location за останньою Wi-Fi-точкою (або None)."""
    s = t.get("last_wifi")
    t["location"] = None
    if not s or not s.get("ap"):
        return t
    rec = locate_ap(s["ap"], idx)
    if not rec:
        t["location"] = {"ap": s["ap"], "known": False}
        return t
    m = idx["maps"].get(rec["map"], {})
    radius_m = float(cfg.get("track_ap_radius_m", 20))
    scale = (cfg.get("track_map_scale_m_per_px") or {}).get(rec["map"])
    t["location"] = {
        "ap": s["ap"], "known": True, "map": rec["map"], "map_name": m.get("name", ""),
        "x": rec["x"], "y": rec["y"], "w": m.get("w"), "h": m.get("h"), "image": m.get("image", ""),
        "radius_m": radius_m,
        "radius_px": (radius_m / float(scale)) if scale else None,
    }
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
        "location": t.get("location"),
    }
