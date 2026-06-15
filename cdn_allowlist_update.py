"""cdn_allowlist_update.py — динамічне наповнення CDN/SaaS-allowlist для UC-02-1.

Проблема: правило UC-02-1 (rule 100521) спрацьовує, коли destination IP присутній
у фіді X-Force "Botnet C&C IPs" (~101k записів). ~22% цього фіду — це shared-front
IP масових CDN/SaaS (Cloudflare домінує), за якими сидять легітимні сайти. Звідси
мережевий вал FP-офенсів.

Чому не CIDR-у-рефсет: QRadar 7.5 reference set приймає ЛИШЕ дискретні IP, не CIDR.
Хитрість ("intersection trick"): єдині CDN-адреси, що взагалі тригерять правило — це
ті, що ВЖЕ є у "Botnet C&C IPs". Тож беремо перетин (фід ∩ провайдерські діапазони)
— це обмежений набір ДИСКРЕТНИХ IP (~22k) — і кладемо його в окремий refset
ME-CDN-Botnet-FP-Allowlist. Правило виключає цей refset → офенси на CDN-фронти не
створюються. Динамічно, без хардкоду CIDR, самочиститься при оновленні фіду X-Force.

Налаштування — лише config.json (ти вказуєш ЩО виключати, скрипт сам тягне мережі):
  cdn_allowlist_providers     — список провайдерів з автозабором діапазонів
  cdn_allowlist_static_cidrs  — ручні CIDR (Apple/Meta — у них немає доступного API звідси)
  cdn_allowlist_target_set    — куди писати (дефолт ME-CDN-Botnet-FP-Allowlist)
  cdn_allowlist_botnet_set    — джерело-фід (дефолт "Botnet C&C IPs")
  cdn_allowlist_dry_run       — true => лише логує, рефсет не чіпає

ОДНОРАЗОВО (вручну, бо це зміни в проді):
  1) створити refset target_set (element_type IP);
  2) у rule 100521 додати тест "and NOT when destination IP is contained in
     ME-CDN-Botnet-FP-Allowlist" + Deploy Changes.
Далі цей скрипт (cron/systemd timer, раз на добу) тримає набір актуальним.

Запуск: python3 /opt/qradar-middleware/cdn_allowlist_update.py [--dry-run]
Lock: cdn_allowlist_update.lock | Log: cdn_allowlist_update.log
"""
import os
import sys
import json
import time
import bisect
import logging
import ipaddress
import fcntl
import urllib.parse

import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
LOCK_FILE = os.path.join(BASE_DIR, "cdn_allowlist_update.lock")
LOG_FILE = os.path.join(BASE_DIR, "cdn_allowlist_update.log")

UA = {"User-Agent": "curl/8", "Accept": "*/*"}

DEFAULTS = {
    "cdn_allowlist_providers": ["cloudflare", "fastly", "google", "aws_cloudfront", "github"],
    # Apple (17/8) та Meta не мають доступного з mdlwr01 ranges-API (bgpview не резолвиться),
    # тож їхні стабільні діапазони задаємо статично — перетин усе одно звужує до фіду.
    "cdn_allowlist_static_cidrs": [
        "17.0.0.0/8",  # Apple
        "157.240.0.0/16", "31.13.24.0/21", "31.13.64.0/18", "57.144.0.0/14",
        "66.220.144.0/20", "69.63.176.0/20", "69.171.224.0/19", "129.134.0.0/16",
        "173.252.64.0/18", "179.60.192.0/22", "185.60.216.0/22", "204.15.20.0/22",
        "195.5.51.0/24",  # Meta / Facebook / Instagram / WhatsApp
    ],
    "cdn_allowlist_target_set": "ME-CDN-Botnet-FP-Allowlist",
    "cdn_allowlist_botnet_set": "Botnet C&C IPs",
    "cdn_allowlist_http_timeout": 30,
    "cdn_allowlist_max_ips": 60000,  # запобіжник: не вантажити аномально великий набір
    "cdn_allowlist_dry_run": False,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)


def load_config() -> dict:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def cfg(config: dict, key: str):
    return config.get(key, DEFAULTS[key])


# --- Провайдери: кожен повертає список IPv4 CIDR-рядків ------------------------

def _get(url: str, timeout: int) -> str:
    return requests.get(url, headers=UA, timeout=timeout).text


def fetch_cloudflare(t):
    return [l.strip() for l in _get("https://www.cloudflare.com/ips-v4", t).splitlines() if l.strip()]


def fetch_fastly(t):
    return json.loads(_get("https://api.fastly.com/public-ip-list", t)).get("addresses", [])


def fetch_google(t):
    d = json.loads(_get("https://www.gstatic.com/ipranges/goog.json", t))
    return [p["ipv4Prefix"] for p in d.get("prefixes", []) if "ipv4Prefix" in p]


def fetch_aws_cloudfront(t):
    d = json.loads(_get("https://ip-ranges.amazonaws.com/ip-ranges.json", t))
    return [p["ip_prefix"] for p in d.get("prefixes", []) if p.get("service") == "CLOUDFRONT"]


def fetch_github(t):
    d = json.loads(_get("https://api.github.com/meta", t))
    return [x for k in ("web", "api", "git") for x in d.get(k, []) if ":" not in x]


def fetch_meta(t):
    d = json.loads(_get("https://api.bgpview.io/asn/32934/prefixes", t))
    return [p["prefix"] for p in d["data"]["ipv4_prefixes"]]


def fetch_apple(t):
    d = json.loads(_get("https://api.bgpview.io/asn/714/prefixes", t))
    return [p["prefix"] for p in d["data"]["ipv4_prefixes"]]


PROVIDERS = {
    "cloudflare": fetch_cloudflare,
    "fastly": fetch_fastly,
    "google": fetch_google,
    "aws_cloudfront": fetch_aws_cloudfront,
    "github": fetch_github,
    "meta": fetch_meta,
    "apple": fetch_apple,
}


def collect_cidrs(config) -> list:
    """Тягне діапазони обраних провайдерів + статичні CIDR. Недосяжний провайдер —
    warning, не падаємо (intersection просто буде трохи менший)."""
    timeout = cfg(config, "cdn_allowlist_http_timeout")
    cidrs = []
    for name in cfg(config, "cdn_allowlist_providers"):
        fn = PROVIDERS.get(name)
        if not fn:
            logging.warning(f"Невідомий провайдер '{name}' — пропускаю.")
            continue
        try:
            got = fn(timeout)
            cidrs.extend(got)
            logging.info(f"Провайдер {name}: {len(got)} діапазонів.")
        except Exception as e:
            logging.warning(f"Провайдер {name}: збій ({type(e).__name__}: {str(e)[:80]}) — пропускаю.")
    static = cfg(config, "cdn_allowlist_static_cidrs")
    if static:
        cidrs.extend(static)
        logging.info(f"Статичні CIDR: {len(static)}.")
    return cidrs


def build_ranges(cidrs: list):
    """Список (start,end) int-діапазонів IPv4, відсортований — для bisect-пошуку."""
    ranges = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
            if n.version == 4:
                ranges.append((int(n.network_address), int(n.broadcast_address)))
        except ValueError:
            logging.warning(f"Некоректний CIDR '{c}' — пропускаю.")
    ranges.sort()
    return ranges


def in_ranges(ip_int: int, ranges, starts) -> bool:
    i = bisect.bisect_right(starts, ip_int) - 1
    # діапазони можуть перекриватись — підстрахуємось кількома кроками назад
    while i >= 0 and ranges[i][0] <= ip_int:
        if ip_int <= ranges[i][1]:
            return True
        i -= 1
    return False


# --- QRadar reference data ----------------------------------------------------

def get_refset_values(api, headers, name, timeout) -> list:
    url = f"{api}/reference_data/sets/{urllib.parse.quote(name)}?fields=data"
    r = requests.get(url, headers=headers, verify=False, timeout=timeout)
    r.raise_for_status()
    return [x["value"] for x in r.json().get("data", [])]


def ensure_set(api, headers, name):
    url = f"{api}/reference_data/sets?name={urllib.parse.quote(name)}&element_type=IP"
    r = requests.post(url, headers=headers, verify=False, timeout=30)
    if r.status_code in (200, 201):
        logging.info(f"Рефсет {name} створено.")
    elif r.status_code == 409:
        logging.info(f"Рефсет {name} вже існує.")
    else:
        logging.warning(f"Створення рефсету {name}: HTTP {r.status_code} {r.text[:160]}")


def purge_set(api, headers, name):
    url = f"{api}/reference_data/sets/{urllib.parse.quote(name)}?purge_only=true"
    r = requests.delete(url, headers=headers, verify=False, timeout=60)
    logging.info(f"Purge {name}: HTTP {r.status_code}")


def bulk_load(api, headers, name, values):
    url = f"{api}/reference_data/sets/bulk_load/{urllib.parse.quote(name)}"
    h = dict(headers); h["Content-Type"] = "application/json"
    r = requests.post(url, headers=h, data=json.dumps(values), verify=False, timeout=180)
    r.raise_for_status()
    return r.json()


def main() -> None:
    dry_cli = "--dry-run" in sys.argv
    config = load_config()
    api = f"{config['qradar_url']}/api"
    headers = {"SEC": config["qradar_token"], "Accept": "application/json"}
    timeout = cfg(config, "cdn_allowlist_http_timeout")
    dry_run = dry_cli or bool(cfg(config, "cdn_allowlist_dry_run"))
    target = cfg(config, "cdn_allowlist_target_set")
    feed = cfg(config, "cdn_allowlist_botnet_set")
    max_ips = cfg(config, "cdn_allowlist_max_ips")

    lock_fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logging.info("Інший запуск ще працює — виходжу.")
        return

    try:
        logging.info(f"=== CDN-allowlist update start (dry_run={dry_run}) ===")
        ranges = build_ranges(collect_cidrs(config))
        if not ranges:
            logging.error("Жодного діапазону провайдерів — нічого не роблю (fail-safe).")
            return
        starts = [r[0] for r in ranges]
        logging.info(f"Усього провайдерських діапазонів: {len(ranges)}.")

        feed_ips = get_refset_values(api, headers, feed, max(timeout, 180))
        logging.info(f"Фід '{feed}': {len(feed_ips)} записів.")

        allow = []
        for v in feed_ips:
            try:
                ipi = int(ipaddress.ip_address(v))
            except ValueError:
                continue
            if in_ranges(ipi, ranges, starts):
                allow.append(v)
        logging.info(f"Перетин фід ∩ CDN: {len(allow)} дискретних IP → '{target}'.")

        if len(allow) > max_ips:
            logging.error(f"Перетин {len(allow)} > запобіжник {max_ips} — НЕ оновлюю (підозра на помилку).")
            return

        if dry_run:
            logging.info(f"[DRY-RUN] Замінив би '{target}' на {len(allow)} IP. Перші 5: {allow[:5]}")
            return

        ensure_set(api, headers, target)
        purge_set(api, headers, target)
        if allow:
            res = bulk_load(api, headers, target, allow)
            logging.info(f"bulk_load '{target}': {res}")
        logging.info(f"=== Готово: '{target}' = {len(allow)} IP ===")
    finally:
        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        lock_fh.close()


if __name__ == "__main__":
    main()
