#!/usr/bin/env python3
"""Знімок стану QRadar до/після оновлення і порівняння двох знімків (лише читання).

    python3 tools/qradar_upgrade_check.py snapshot [файл.json]   # без файлу — друк у stdout
    python3 tools/qradar_upgrade_check.py diff до.json після.json

Збирає через REST (config.json: qradar_url, qradar_token): версію, хости розгортання, застосунки
(версія + статус), log source'и за статусом, відкриті офенси, увімкнені правила, reference sets,
потік подій за 15 хв (кількість + скільки log source'ів його дають). `diff` показує лише те, що
змінилось, і окремо червоним прапорцем — що погіршилось (застосунок не RUNNING, log source'ів
у помилці побільшало, потік подій упав більш ніж на 30%). План — docs/changes/2026-11-18-qradar-upgrade-76-plan.md.
"""
import json
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()
CONFIG = "/opt/qradar-middleware/config.json"


def session():
    c = json.load(open(CONFIG))
    return c["qradar_url"].rstrip("/") + "/api", {"SEC": c["qradar_token"], "Accept": "application/json",
                                                    "Version": "19.0"}


def get(base, h, path, rng=None, **params):
    hh = dict(h)
    if rng:
        hh["Range"] = f"items={rng}"
    r = requests.get(base + path, headers=hh, params=params, verify=False, timeout=120)
    r.raise_for_status()
    return r


def total(base, h, path, **params):
    r = get(base, h, path, "0-0", **params)
    cr = r.headers.get("Content-Range", "")
    return int(cr.rsplit("/", 1)[-1]) if "/" in cr else len(r.json())


def aql(base, h, query, timeout=180):
    r = requests.post(base + "/ariel/searches", headers=h, params={"query_expression": query}, verify=False, timeout=60)
    r.raise_for_status()
    sid = r.json()["search_id"]
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = requests.get(f"{base}/ariel/searches/{sid}", headers=h, verify=False, timeout=60).json()
        if s.get("status") == "COMPLETED":
            res = requests.get(f"{base}/ariel/searches/{sid}/results", headers=h, verify=False, timeout=60).json()
            requests.delete(f"{base}/ariel/searches/{sid}", headers=h, verify=False, timeout=30)
            return res.get("events") or []
        if s.get("status") in ("ERROR", "CANCELED"):
            break
        time.sleep(3)
    requests.delete(f"{base}/ariel/searches/{sid}", headers=h, verify=False, timeout=30)
    return None


def snapshot() -> dict:
    base, h = session()
    out: dict = {"ts": time.strftime("%Y-%m-%d %H:%M:%S")}
    out["about"] = get(base, h, "/system/about").json().get("release_name")
    out["hosts"] = {x["hostname"]: x["private_ip"] for x in get(base, h, "/config/deployment/hosts").json()}
    apps = get(base, h, "/gui_app_framework/applications").json()
    out["apps"] = {a.get("manifest", {}).get("name"): f"{a.get('manifest', {}).get('version')} "
                   f"{(a.get('application_state') or {}).get('status')}" for a in apps}
    ls = get(base, h, "/config/event_sources/log_source_management/log_sources", "0-9999",
             fields="id,enabled,status").json()
    by: dict = {}
    for x in ls:
        st = x.get("status")
        st = st.get("status") if isinstance(st, dict) else st
        key = f"{'on' if x.get('enabled') else 'off'}:{st}"
        by[key] = by.get(key, 0) + 1
    out["log_sources"] = dict(sorted(by.items()))
    out["offenses_open"] = total(base, h, "/siem/offenses", filter='status="OPEN"', fields="id")
    out["rules_enabled"] = total(base, h, "/analytics/rules", filter="enabled=true", fields="id")
    out["reference_sets"] = total(base, h, "/reference_data/sets", fields="name")
    ev = aql(base, h, "SELECT COUNT(*) AS c, UNIQUECOUNT(logsourceid) AS ls FROM events LAST 15 MINUTES")
    out["events_15m"] = {"events": (ev[0].get("c") if ev else None), "log_sources": (ev[0].get("ls") if ev else None)} \
        if ev else None
    return out


def flat(d: dict, prefix: str = "") -> dict:
    o: dict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            o.update(flat(v, f"{prefix}{k}."))
        else:
            o[f"{prefix}{k}"] = v
    return o


def diff(a: dict, b: dict) -> int:
    fa, fb = flat(a), flat(b)
    bad = 0
    for k in sorted(set(fa) | set(fb)):
        if k == "ts" or fa.get(k) == fb.get(k):
            continue
        flag = ""
        if k.startswith("apps.") and "RUNNING" not in str(fb.get(k)):
            flag = "  <<< ЗАСТОСУНОК НЕ RUNNING"
        if k.startswith("log_sources.") and ":ERROR" in k and (fb.get(k) or 0) > (fa.get(k) or 0):
            flag = "  <<< БІЛЬШЕ LOG SOURCE У ПОМИЛЦІ"
        if k == "events_15m.events" and fa.get(k) and (fb.get(k) or 0) < 0.7 * fa[k]:
            flag = "  <<< ПОТІК ПОДІЙ УПАВ >30%"
        if flag:
            bad += 1
        print(f"{k}: {fa.get(k)} -> {fb.get(k)}{flag}")
    print(f"\nпогіршень: {bad}")
    return 1 if bad else 0


def main() -> None:
    args = sys.argv[1:]
    if args[:1] == ["snapshot"]:
        s = snapshot()
        txt = json.dumps(s, ensure_ascii=False, indent=1)
        if len(args) > 1:
            open(args[1], "w").write(txt)
            print(f"записано {args[1]}")
        print(txt)
    elif args[:1] == ["diff"] and len(args) == 3:
        sys.exit(diff(json.load(open(args[1])), json.load(open(args[2]))))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
