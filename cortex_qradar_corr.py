#!/usr/bin/env python3
"""
Зведення Cortex ↔ QRadar по хосту: до кожного інциденту Cortex «на перегляд» додаємо відкриті офенси QRadar
за той самий хост (ім'я або IP) за останні N годин. Лише читання QRadar REST; у звіті це рядок `🔗 QRadar: …`.

Ключ збігу: IP, або коротке ім'я (до першої крапки, нижній регістр). Хости Cortex бувають `name:endpoint_id`,
`ip:ip` і `NO_HOST…:ip`. DNS-форвардери/проксі (`cortex_xdr_pavm_dns_proxy_ips`, `cortex_xdr_dns_forwarders`) у збіг
не беруться: їх адреса стоїть замість справжнього клієнта, тож з'єднала б сторонні офенси. Збій QRadar не валить звіт.
"""
import ipaddress
import logging
import time

import requests
import urllib3

urllib3.disable_warnings()

DEFAULTS = {
    "cortex_incident_qradar_corr": True,
    "cortex_incident_qradar_corr_hours": 72,       # офенси, оновлені за останні N годин
    "cortex_incident_qradar_corr_min_magnitude": 5,
    "cortex_incident_qradar_corr_per_incident": 3,  # скільки офенсів показати під одним інцидентом
}


def cfg(config: dict, key: str):
    return config.get(key, DEFAULTS[key])


def norm(value: str) -> str:
    """IP як є; ім'я → коротке нижнім регістром; порожнє/службове → ''."""
    v = (value or "").strip().lower()
    if not v or v.startswith("no_host"):
        return ""
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return v.split(".")[0]


def cortex_keys(host: str) -> set:
    """Ключі хоста Cortex: `name:id` → {name}; `ip:ip` → {ip}; `NO_HOST…:ip` → {ip}."""
    a, _, b = (host or "").partition(":")
    out = {norm(b)} if a.lower().startswith("no_host") else {norm(a)}
    if a.lower().startswith("no_host") is False and norm(a) == "":
        out.add(norm(b))
    return {k for k in out if k}


def fetch_offenses(config: dict, hours: float, min_mag: int) -> list | None:
    base = str(config.get("qradar_url") or "").rstrip("/")
    token = config.get("qradar_token")
    if not base or not token:
        logging.warning("qradar_corr: немає qradar_url/qradar_token")
        return None
    since = int((time.time() - hours * 3600) * 1000)
    try:
        r = requests.get(f"{base}/api/siem/offenses", verify=False, timeout=90,
                         headers={"SEC": token, "Accept": "application/json", "Version": "19.0", "Range": "items=0-4999"},
                         params={"filter": f'status="OPEN" and magnitude>={int(min_mag)} and last_updated_time>{since}',
                                 "fields": "id,description,offense_source,magnitude"})
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as e:
        logging.warning(f"qradar_corr: QRadar недоступний: {type(e).__name__}")
        return None


def correlate(review: list, offenses: list, exclude: set, per_incident: int) -> dict:
    """review = [(incident, why)] → {incident_id: [offense,…]} (за спаданням magnitude)."""
    by_key: dict = {}
    for o in offenses or []:
        k = norm(str(o.get("offense_source") or ""))
        if k and k not in exclude:
            by_key.setdefault(k, []).append(o)
    out: dict = {}
    for inc, _why in review:
        seen, hits = set(), []
        for h in inc.get("hosts") or []:
            for k in cortex_keys(h):
                if k in exclude:
                    continue
                for o in by_key.get(k, []):
                    if o["id"] not in seen:
                        seen.add(o["id"])
                        hits.append(o)
        if hits:
            hits.sort(key=lambda o: -int(o.get("magnitude") or 0))
            out[str(inc.get("incident_id"))] = {"total": len(hits), "top": hits[:per_incident]}
    return out


def build(config: dict, review: list, exclude: set) -> dict:
    """Повертає {incident_id: {total, top}} або {} (вимкнено / нема збігів / QRadar недоступний)."""
    if not cfg(config, "cortex_incident_qradar_corr") or not review:
        return {}
    offenses = fetch_offenses(config, float(cfg(config, "cortex_incident_qradar_corr_hours")),
                              int(cfg(config, "cortex_incident_qradar_corr_min_magnitude")))
    if not offenses:
        return {}
    corr = correlate(review, offenses, exclude, int(cfg(config, "cortex_incident_qradar_corr_per_incident")))
    logging.info(f"qradar_corr: офенсів QRadar {len(offenses)}, інцидентів Cortex зі збігом {len(corr)}/{len(review)}")
    return corr


def line(config: dict, c: dict) -> str:
    base = str(config.get("qradar_url") or "").rstrip("/")
    parts = []
    for o in c["top"]:
        ref = f"#{o['id']}"
        if base:
            ref = f"<{base}/console/qradar.jsp?appName=Sem&pageId=OffenseSummary&summaryId={o['id']}|#{o['id']}>"
        parts.append(f"{ref} [m{o.get('magnitude')}] {(o.get('description') or '').replace(chr(10), ' ')[:60]}")
    more = f" (+ще {c['total'] - len(c['top'])})" if c["total"] > len(c["top"]) else ""
    return f"   🔗 QRadar, відкриті офенси того ж хоста: {'; '.join(parts)}{more}"
