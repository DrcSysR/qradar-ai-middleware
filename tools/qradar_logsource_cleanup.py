#!/usr/bin/env python3
"""Видалення мертвих log source'ів QRadar за списком id. За замовчуванням DRY-RUN.

    python3 tools/qradar_logsource_cleanup.py ids.json [--key tier1_safe] [--apply] [--max N]

`ids.json` — або список id, або словник {ім'я_групи: [id…]} (тоді `--key` обов'язковий).
Перед видаленням КОЖЕН id перевіряється наживо: статус ERROR/DISABLED, остання подія старша за
`--min-age-days` (90) і немає подій за останні 24 год. Повне визначення log source'а зберігається у
`logsource_cleanup_backup_<ts>.json` (з нього можна відтворити), хід — у `logsource_cleanup.log`.
Видалення необоротне; події в Ariel лишаються, але втрачають прив'язку до імені log source'а.
Пристрій, що знову почне слати логи, автоматично створить новий log source (для WindowsAuthServer / Linux).
"""
import json
import logging
import sys
import time

import requests
import urllib3

import qradar_upgrade_check as u

urllib3.disable_warnings()
LOG = "/opt/qradar-middleware/logsource_cleanup.log"
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s",
                    handlers=[logging.FileHandler(LOG), logging.StreamHandler()])
PATH = "/config/event_sources/log_source_management/log_sources"


def main() -> None:
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        sys.exit(2)
    apply = "--apply" in a
    min_age = float(a[a.index("--min-age-days") + 1]) if "--min-age-days" in a else 90.0
    max_n = int(a[a.index("--max") + 1]) if "--max" in a else 10 ** 9
    data = json.load(open(a[0]))
    if isinstance(data, dict):
        if "--key" not in a:
            sys.exit(f"вкажіть --key з: {', '.join(data)}")
        data = data[a[a.index("--key") + 1]]
    ids = [int(i) for i in data][:max_n]
    base, h = u.session()
    now = time.time() * 1000
    ts = time.strftime("%Y%m%d_%H%M%S")
    backup, done, skipped = [], 0, []
    logging.info(f"=== log source cleanup: {len(ids)} id, {'APPLY' if apply else 'DRY-RUN'}, min_age={min_age:g}d ===")
    for i in ids:   # прохід 1: жива перевірка кожного id
        r = requests.get(f"{base}{PATH}/{i}", headers=h, verify=False, timeout=60)
        if r.status_code == 404:
            skipped.append((i, "вже немає"))
            continue
        r.raise_for_status()
        x = r.json()
        st = (x.get("status") or {}).get("status")
        le = x.get("last_event_time") or 0
        age = (now - le) / 86400000 if le else 1e9
        if st not in ("ERROR", "DISABLED") or age < min_age:
            skipped.append((i, f"не мертвий: status={st} age={age:.0f}d"))
            logging.warning(f"SKIP {i} {x.get('name')}: status={st} age={age:.0f}d")
            continue
        backup.append((x, age))
    if apply and backup:   # визначення зберігаємо ДО першого видалення
        fn = f"/opt/qradar-middleware/logsource_cleanup_backup_{ts}.json"
        json.dump([x for x, _ in backup], open(fn, "w"), ensure_ascii=False)
        logging.info(f"визначення збережено: {fn}")
    for x, age in backup:   # прохід 2: видалення
        i = x["id"]
        if not apply:
            logging.info(f"[dry-run] delete {i} {x.get('name')} (остання подія {age:.0f} д тому)")
            continue
        d = requests.delete(f"{base}{PATH}/{i}", headers={**h, "Accept": "text/plain"}, verify=False, timeout=60)   # DELETE віддає 406 на Accept: application/json
        if d.status_code in (200, 202, 204):
            done += 1
            logging.info(f"deleted {i} {x.get('name')} -> HTTP {d.status_code}")
        else:
            skipped.append((i, f"HTTP {d.status_code}: {d.text[:120]}"))
            logging.error(f"FAIL {i} {x.get('name')}: HTTP {d.status_code} {d.text[:200]}")
        time.sleep(0.3)
    logging.info(f"підсумок: {'видалено' if apply else 'було б видалено'} {done if apply else len(backup)}, пропущено {len(skipped)}")
    for i, why in skipped[:20]:
        logging.info(f"  пропущено {i}: {why}")


if __name__ == "__main__":
    main()
