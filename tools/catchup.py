"""Догінний прохід по офенсах, яких штатний поллер не бачить.

Поллер бере лише вікно `LOOKBACK_TIME_MS` (48 год) і пропускає все, що має нотатку
«AI Analysis» — включно з нотаткою «AI Analysis (SKIPPED)», яку сам мідлварь пише на
AQL_ERROR і NO_EVENTS. Через це утворюються два бакети, які не розбирає ніхто:

  1) офенс матчиться в prompts.json, але старший за 48 год — випав із вікна назавжди;
  2) офенс має статус AQL_ERROR / NO_EVENTS — нотатка вже стоїть, тож `has_ai_note`
     у поллері його більше ніколи не візьме, хоча коментар у app.py обіцяє повтор.

ЧОМУ ПРОСТИЙ ПОВТОР НЕ ПРАЦЮЄ (переміряно 02.09.2026). Обидва застряглі бакети — це
довгоживучі офенси (QRadar доливає в них події тижнями). Вікно AQL прив'язане до
start/end офенсу, тож розмах = тривалість офенсу, обрізана стелею `max_aql_span_hours`
(192 год). Пошук на 8 діб по гучному лог-сорсу не завершується за
`aql_poll_timeout_seconds` (180 с) → знову AQL_ERROR. Тому прохід за замовчуванням
шле `max_span_hours: 12` — свіжий хвіст офенсу, а не вся його історія. Це і є той
параметр, який робить повтор осмисленим.

Цей скрипт добирає саме їх і шле у той самий `POST /universal-analysis`, що й поллер
(`is_manual: false` — модель і вікно ті самі, що в авто-режимі; вікно AQL прив'язане до
start/end самого офенсу, тому вік офенсу ролі не грає, а розмах обмежений
`max_aql_span_hours`).

Запуск на mdlwr01 (файл, не через stdin — потрібні аргументи):

    python3 /opt/qradar-middleware/tools/catchup.py --stats
    python3 /opt/qradar-middleware/tools/catchup.py --only-retry --dry-run
    python3 /opt/qradar-middleware/tools/catchup.py --only-retry
    nohup python3 /opt/qradar-middleware/tools/catchup.py --concurrency 2 &

Окремий режим — прогін конкретних ID через ПОТОЧНИЙ пайплайн (після правки промпта чи
AQL старі офенси ніхто не переоцінює: `PROCESSED` більше не беруть ні поллер, ні цей
прохід). Свій lock-файл, тож не чекає фонового проходу:

    python3 /opt/qradar-middleware/tools/catchup.py --offenses 1253238,1266116 --manual

Свій lock-файл (`catchup.lock`) і свій лог (`catchup.log`) — з поллером не конфліктує,
але за замовчуванням тримається від його вікна подалі (`--min-age-hours 48`), щоб не
дублювати роботу. Конкурентність за замовчуванням 2, бо llm01 має 3 слоти й поллер уже
займає їх: сумарний тиск понад ~4 паралельних запити піднімає частку відмов tier-1
(переміряно 28.08 при poller_concurrency 5 — 92% відмов).
"""

import argparse
import fcntl
import json
import logging
import os
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

BASE_DIR = "/opt/qradar-middleware"
sys.path.insert(0, BASE_DIR)
from prompts_loader import get_rule_keys, matched_rule_key  # noqa: E402

CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
PROMPTS_FILE = os.path.join(BASE_DIR, "prompts.json")
DB_PATH = os.path.join(BASE_DIR, "ai_state.db")
LOG_FILE = os.path.join(BASE_DIR, "catchup.log")
LOCK_FILE = os.path.join(BASE_DIR, "catchup.lock")
MIDDLEWARE_URL = "http://127.0.0.1:5000/universal-analysis"

PAGE = 1000  # Range-пагінація: без неї QRadar на наших обсягах віддає обрізаний JSON
RETRYABLE = ("AQL_ERROR", "NO_EVENTS")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_args():
    p = argparse.ArgumentParser(description="Догінний прохід по офенсах поза вікном поллера")
    p.add_argument("--min-age-hours", type=float, default=48.0,
                   help="брати офенси старші за N год (0 = всі; дефолт 48 = не лізти у вікно поллера)")
    p.add_argument("--limit", type=int, default=0, help="стеля на прохід (0 = без стелі)")
    p.add_argument("--concurrency", type=int, default=2, help="паралельних запитів до мідлваря")
    p.add_argument("--retry", default="AQL_ERROR",
                   help="які статуси перезапускати, через кому: AQL_ERROR,NO_EVENTS або none")
    p.add_argument("--only-retry", action="store_true",
                   help="лише перезапуск застряглих статусів, без бакету «ніколи не бачених»")
    p.add_argument("--include-unmatched", action="store_true",
                   help="брати й офенси без ключа в prompts.json (піде Default-промпт)")
    p.add_argument("--window-hours", type=float, default=0.0,
                   help="вікно AQL на офенс (0 = дефолт мідлваря, auto_window_hours)")
    p.add_argument("--max-span-hours", type=float, default=12.0,
                   help="стеля на РОЗМАХ вікна AQL. Головний параметр проходу: у застряглих "
                        "офенсів дефолтні 192 год не встигають за aql_poll_timeout_seconds "
                        "(180 с) і повтор падає в той самий AQL_ERROR. 0 = дефолт мідлваря")
    p.add_argument("--offenses", default="",
                   help="прогнати саме ці ID (через кому), без класифікації. Для переоцінки "
                        "вже протріажованих офенсів після правки промпта чи AQL")
    p.add_argument("--force", action="store_true",
                   help="переоцінити вже оброблені офенси в АВТО-режимі: обходить перевірку "
                        "«вже оброблено», але лишає авто-дії — score ≤ 0.6 закриє офенс. "
                        "Саме цим завершують цикл після правки промпта")
    p.add_argument("--manual", action="store_true",
                   help="is_manual: true — обходить перевірку «вже оброблено», бере deep-модель "
                        "і manual_window_hours. Автоматично НІЧОГО не закриває: на виході лише "
                        "свіжа нотатка з вердиктом, рішення за аналітиком")
    p.add_argument("--dry-run", action="store_true", help="показати план і вийти")
    p.add_argument("--stats", action="store_true", help="лише розклад відкритих офенсів по бакетах")
    return p.parse_args()


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
    )


def take_lock(path=LOCK_FILE):
    handle = open(path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logging.warning("⚠️ Догінний прохід уже виконується. Новий запуск скасовано.")
        sys.exit(0)
    return handle


def fetch_open_offenses(api, headers):
    """Усі відкриті офенси з пагінацією. fields — мінімум, потрібний для матчингу
    (rules — назви правил-учасників) і для приоритезації (magnitude)."""
    url = f"{api}/siem/offenses"
    params = {"filter": 'status="OPEN"', "fields": "id,description,rules,start_time,magnitude"}
    out, start = [], 0
    while True:
        h = dict(headers, Range=f"items={start}-{start + PAGE - 1}")
        r = requests.get(url, headers=h, params=params, verify=False, timeout=180)
        r.raise_for_status()
        chunk = r.json()
        out.extend(chunk)
        if len(chunk) < PAGE:
            return out
        start += PAGE


def get_rules_map(api, headers):
    try:
        r = requests.get(f"{api}/analytics/rules", headers=headers, params={"fields": "id,name"},
                         verify=False, timeout=60)
        if r.status_code == 200:
            return {item["id"]: item.get("name", "") for item in r.json()}
        logging.warning(f"Мапа правил недоступна: HTTP {r.status_code} — матчимо лише за описом")
    except Exception as exc:
        logging.warning(f"Мапа правил недоступна: {exc} — матчимо лише за описом")
    return {}


def load_state():
    with sqlite3.connect(DB_PATH) as conn:
        return {int(i): s for i, s in conn.execute("SELECT offense_id, status FROM offenses")}


def has_verdict_note(api, headers, offense_id):
    """True лише якщо в офенсі є нотатка з РЕАЛЬНИМ результатом. «AI Analysis (SKIPPED)»
    результатом не є — саме вона й тримає AQL_ERROR/NO_EVENTS вічно непереаналізованими."""
    try:
        r = requests.get(f"{api}/siem/offenses/{offense_id}/notes", headers=headers,
                         verify=False, timeout=15)
        if r.status_code != 200:
            return False
        return any("AI Analysis" in n.get("note_text", "") and "(SKIPPED)" not in n.get("note_text", "")
                   for n in r.json())
    except Exception:
        return False


def classify(offenses, rules_map, rule_keys, state, min_age_ms, retry_statuses,
             only_retry, include_unmatched):
    """Розкладає відкриті офенси по бакетах і повертає (кандидати, розклад).
    Кандидат = (ключ_юзкейсу, magnitude, start_time, offense_id, причина)."""
    now_ms = int(time.time() * 1000)
    buckets = Counter()
    candidates = []
    for off in offenses:
        off_id = int(off["id"])
        desc = off.get("description", "") or ""
        rule_names = [rules_map.get(r.get("id"), "") for r in off.get("rules", [])]
        key = matched_rule_key(rule_keys, desc, rule_names)
        matched = key is not None
        age_ms = now_ms - (off.get("start_time") or 0)
        status = state.get(off_id)
        label = key or desc.replace("\n", " ").strip()[:60] or "—"
        mag = off.get("magnitude") or 0
        start = off.get("start_time") or 0

        if status == "PROCESSED":
            buckets["протріажовано, лишений відкритим (assign)"] += 1
            continue
        if status == "PROCESSING":
            buckets["PROCESSING"] += 1
            continue
        if status in RETRYABLE:
            buckets[f"застряг: {status}"] += 1
            if status in retry_statuses:
                candidates.append((label, mag, start, off_id, status))
            continue
        # немає запису в БД — мідлварь цього офенсу не бачила
        if not matched and not include_unmatched:
            buckets["без юзкейсу в prompts.json"] += 1
            continue
        if age_ms < min_age_ms:
            buckets["у вікні поллера (його робота)"] += 1
            continue
        if only_retry:
            buckets["поза вікном, не бачений (пропущено: --only-retry)"] += 1
            continue
        buckets["поза вікном, не бачений"] += 1
        candidates.append((label, mag, start, off_id, "NEVER_SEEN"))
    return candidates, buckets


def order_candidates(candidates, limit):
    """Кругова роздача по юзкейсах, усередині юзкейсу — спершу вища magnitude, потім
    старіші. Логіка та сама, що в поллері: один гучний юзкейс не має з'їсти прохід.
    Але пріоритет усередині інший — тут дедлайну вже немає (усі поза вікном), тож
    вирішує ймовірність того, що офенс справжній."""
    by_key = defaultdict(list)
    for label, mag, start, off_id, reason in candidates:
        by_key[label].append((-mag, start, off_id, reason))
    for key in by_key:
        by_key[key].sort()

    order = sorted(by_key, key=lambda k: (-len(by_key[k]), k))
    pos = {k: 0 for k in by_key}
    out = []
    while True:
        took = False
        for key in order:
            if limit and len(out) >= limit:
                return out
            i = pos[key]
            if i < len(by_key[key]):
                neg_mag, start, off_id, reason = by_key[key][i]
                pos[key] = i + 1
                out.append((key, -neg_mag, off_id, reason))
                took = True
        if not took:
            return out


def run_queue(args, api, headers, queue, lock_path=LOCK_FILE):
    """Відправляє чергу в мідлварь. Спільне для обох режимів — і класифікованого
    проходу, і прогону за явним списком ID."""
    lock = take_lock(lock_path)  # лок беремо лише перед реальною роботою, щоб --stats/--dry-run не блокувались

    # Нотатку перевіряємо ЛИШЕ для «не бачених»: наявність реального вердикту означає,
    # що офенс уже розібрали (напр. вручну через веб-форму) і БД просто чистили.
    # Для AQL_ERROR/NO_EVENTS нотатка є завжди — і саме вона нас тут і не цікавить.
    outcomes = Counter()
    started = time.time()

    body_extra = {}
    if args.window_hours:
        body_extra["window_hours"] = args.window_hours
    if args.max_span_hours:
        body_extra["max_span_hours"] = args.max_span_hours
    if args.force:
        body_extra["force"] = True
    if body_extra:
        logging.info(f"Вікно AQL для проходу: {body_extra}")

    def process_one(item):
        key, mag, off_id, reason = item
        if reason == "NEVER_SEEN" and has_verdict_note(api, headers, off_id):
            return "skipped_noted", off_id
        try:
            r = requests.post(MIDDLEWARE_URL,
                              json={"offense_id": off_id, "is_manual": args.manual, **body_extra},
                              timeout=600)
            if r.status_code == 200:
                body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                logging.info(f"✅ {off_id} [{reason}] → {body.get('status', 'ok')} "
                             f"{('score ' + str(body['score'])) if 'score' in body else ''}")
                return "ok:" + str(body.get("status", "ok")), off_id
            logging.error(f"❌ {off_id}: HTTP {r.status_code}")
            return "http_error", off_id
        except requests.exceptions.Timeout:
            logging.error(f"⏳ {off_id}: таймаут 600 с")
            return "timeout", off_id
        except requests.exceptions.ConnectionError as exc:
            logging.error(f"❌ {off_id}: немає з'єднання з мідлварем: {exc}")
            return "conn", off_id
        except Exception as exc:
            logging.error(f"❌ {off_id}: {exc}")
            return "err", off_id

    done = 0
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futures = {pool.submit(process_one, item): item[2] for item in queue}
        for fut in as_completed(futures):
            outcome, _ = fut.result()
            outcomes[outcome] += 1
            done += 1
            if outcomes["conn"] >= 5:
                logging.error("🛑 Мідлварь недоступний — припиняю прохід.")
                for pending in futures:
                    pending.cancel()
                break
            if done % 50 == 0:
                rate = done / max(1e-9, time.time() - started)
                left = (len(queue) - done) / max(1e-9, rate) / 60
                logging.info(f"⏱️ {done}/{len(queue)}, {rate * 60:.1f} офенсів/хв, "
                             f"лишилось ~{left:.0f} хв. Проміжно: {dict(outcomes)}")

    logging.info(f"--- Прохід завершено за {(time.time() - started) / 60:.1f} хв: {dict(outcomes)} ---")

    # Чим це закінчилось у БД — головна метрика проходу: чи повтор узагалі допомагає.
    ids = [off_id for _, _, off_id, _ in queue]
    if ids:
        with sqlite3.connect(DB_PATH) as conn:
            marks = ",".join("?" * len(ids))
            after = Counter(s for (s,) in conn.execute(
                f"SELECT status FROM offenses WHERE offense_id IN ({marks})", ids))
        logging.info(f"Статуси в БД після проходу: {dict(after)}")
    lock.close()


def main():
    args = parse_args()
    setup_logging()

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)
    api = f"{config['qradar_url']}/api"
    headers = {"SEC": config["qradar_token"], "Accept": "application/json"}

    retry_statuses = set()
    if args.retry.lower() not in ("none", ""):
        retry_statuses = {s.strip().upper() for s in args.retry.split(",") if s.strip()}
        unknown = retry_statuses - set(RETRYABLE)
        if unknown:
            sys.exit(f"--retry: невідомі статуси {sorted(unknown)}; допустимі {list(RETRYABLE)}")

    # Режим явного списку: класифікацію не робимо взагалі — аналітик уже сказав, що саме
    # прогнати. Свій lock-файл, щоб не чекати довгого фонового проходу.
    if args.offenses:
        ids = [int(x) for x in args.offenses.replace(" ", "").split(",") if x]
        queue = [("explicit", 0, off_id, "EXPLICIT") for off_id in ids]
        logging.info(f"--- Прогон за списком: {len(queue)} офенсів, "
                     f"режим {'manual (deep, без авто-закриття)' if args.manual else 'auto'}"
                     f"{' + force (обхід «вже оброблено», авто-дії увімкнені)' if args.force else ''} ---")
        if args.dry_run:
            logging.info("--dry-run: " + ", ".join(str(i) for i in ids))
            return
        run_queue(args, api, headers, queue, lock_path=LOCK_FILE.replace(".lock", "_ids.lock"))
        return

    rule_keys = get_rule_keys(PROMPTS_FILE)
    offenses = fetch_open_offenses(api, headers)
    rules_map = get_rules_map(api, headers)
    state = load_state()

    candidates, buckets = classify(
        offenses, rules_map, rule_keys, state,
        int(args.min_age_hours * 3600 * 1000), retry_statuses,
        args.only_retry, args.include_unmatched,
    )

    logging.info(f"--- Догінний прохід: відкритих офенсів {len(offenses)} ---")
    for name, count in buckets.most_common():
        logging.info(f"   {count:6d}  {name}")

    if args.stats:
        return

    queue = order_candidates(candidates, args.limit)
    shape = Counter(reason for _, _, _, reason in queue)
    logging.info(f"Кандидатів: {len(candidates)}, у прохід беремо {len(queue)} — {dict(shape)}")
    top = Counter(key for key, _, _, _ in queue).most_common(8)
    logging.info("Топ юзкейсів у проході: " + ", ".join(f"{k[:34]} {v}" for k, v in top))

    if args.dry_run:
        logging.info("--dry-run: нічого не відправляю.")
        for key, mag, off_id, reason in queue[:20]:
            logging.info(f"   план: {off_id} mag={mag} [{reason}] {key[:50]}")
        return

    run_queue(args, api, headers, queue)


if __name__ == "__main__":
    main()
