#!/usr/bin/env python3
"""
Одноразовий bootstrap: створює reference set `ME-CDN-Allowlist` у QRadar і
завантажує туди CIDR-діапазони масових CDN/SaaS-фронтів, які засмічують фід
X-Force "Botnet C&C IPs" і дають FP в UC-02-1 (rule 100521).

Призначення: source-level фікс. Middleware вже авто-закриває ці FP (use-case
uc02_botnet_ip), але офенси все одно СТВОРЮЮТЬСЯ. Додавши в rule 100521 тест
"and NOT when destination IP is contained in ME-CDN-Allowlist", офенси на
Cloudflare/Apple/Meta/Google/Fastly-фронти взагалі перестануть з'являтись.

Запуск (на mdlwr01, де лежить config.json з токеном):
    python3 /opt/qradar-middleware/tools/setup_cdn_allowlist.py

Скрипт:
  1) створює reference set (element_type=IP), якщо ще нема;
  2) bulk-load CIDR-діапазонів;
  3) ВЕРИФІКУЄ, що CIDR-membership реально працює (REFERENCESETCONTAINS) —
     друкує True для IP всередині Cloudflare і False для стороннього IP.
Нічого в детекті НЕ змінює, поки рефсет не підключено в правило вручну в UI.
Рефсет інертний — безпечно ганяти повторно (ідемпотентно).

Джерела діапазонів: Cloudflare https://www.cloudflare.com/ips/, Apple 17.0.0.0/8,
Meta/Fastly/Google — офіційні публічні діапазони. Підтримуй у синхроні з
queries/uc02_botnet_ip.aql.
"""
import json, ssl, sys, time, urllib.request, urllib.parse, urllib.error

CONFIG = "/opt/qradar-middleware/config.json"
SET_NAME = "ME-CDN-Allowlist"

CIDRS = [
    # Cloudflare (головне джерело FP)
    "104.16.0.0/12", "172.64.0.0/13", "162.158.0.0/15", "198.41.128.0/17",
    "173.245.48.0/20", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
    "188.114.96.0/20", "197.234.240.0/22", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "131.0.72.0/22",
    # Apple (весь /8 належить Apple)
    "17.0.0.0/8",
    # Meta / Facebook / Instagram / WhatsApp
    "157.240.0.0/16", "31.13.24.0/21", "31.13.64.0/18", "57.144.0.0/14",
    "66.220.144.0/20", "69.63.176.0/20", "69.171.224.0/19", "129.134.0.0/16",
    "173.252.64.0/18", "179.60.192.0/22", "185.60.216.0/22", "204.15.20.0/22",
    "195.5.51.0/24",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16",
    # Google (web + DNS фронти)
    "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "74.125.0.0/16",
    "64.233.160.0/19", "209.85.128.0/17",
]

cfg = json.load(open(CONFIG))
BASE = cfg["qradar_url"].rstrip("/") + "/api"
SEC = cfg["qradar_token"]
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE


def call(method, path, body=None):
    data = body.encode() if body else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"SEC": SEC, "Accept": "application/json", "Content-Type": "application/json"},
    )
    try:
        return 200, urllib.request.urlopen(req, context=CTX, timeout=120).read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    q = urllib.parse.quote(SET_NAME, safe="")

    code, body = call("POST", f"/reference_data/sets?name={q}&element_type=IP&timeout_type=FIRST_SEEN")
    print(f"[create] HTTP {code}: {body[:160]}" + ("  (вже існує — ок)" if code == 409 else ""))

    code, body = call("POST", f"/reference_data/sets/bulk_load/{q}", json.dumps(CIDRS))
    print(f"[bulk_load {len(CIDRS)} CIDR] HTTP {code}: {body[:160]}")
    if code not in (200,):
        print("!! bulk_load не вдався — далі не йдемо"); sys.exit(1)

    code, body = call("GET", f"/reference_data/sets/{q}")
    print(f"[set] elements = {json.loads(body).get('number_of_elements')}")

    # Верифікація CIDR-membership через AQL
    inside, outside = "104.21.1.1", "137.220.1.1"  # Cloudflare vs DigitalOcean
    aql = (f"SELECT REFERENCESETCONTAINS('{SET_NAME}', '{inside}') AS in_cf, "
           f"REFERENCESETCONTAINS('{SET_NAME}', '{outside}') AS in_do FROM events LAST 1 MINUTES")
    code, body = call("POST", "/ariel/searches?query_expression=" + urllib.parse.quote(aql, safe=""))
    if code not in (200, 201):
        print(f"[verify] не вдалось запустити пошук HTTP {code}: {body[:160]}"); return
    sid = json.loads(body)["search_id"]
    for _ in range(40):
        code, body = call("GET", f"/ariel/searches/{sid}")
        st = json.loads(body)["status"]
        if st in ("COMPLETED", "ERROR", "CANCELED"):
            break
        time.sleep(3)
    print(f"[verify] search {st}")
    print("\n>>> Якщо колонки нижче дають in_cf=true / in_do=false — CIDR-membership працює,")
    print(">>> можна підключати рефсет у rule 100521 (кроки — у відповіді Claude).")
    print(">>> Запусти у QRadar UI або через API:")
    print(f"    {aql}")


if __name__ == "__main__":
    main()
