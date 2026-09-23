"""Консюмер черги work_queue: забирає офенси в порядку magnitude DESC → manual →
найстаріші і віддає їх у внутрішній POST /process-one мідлваря.

Дзеркало poller.py за формою (systemd oneshot-таймер, fcntl-лок, лог у файл), але
роль протилежна: поллер лише КЛАДЕ в чергу, воркер лише ЗАБИРАЄ з неї. Сам аналіз
(AQL, лінзи, LLM, каскад, нотатки, закриття) живе в app.py і не змінювався.

Один ран = дренаж до порожньої черги (worker_batch_per_run=0) або до стелі. Таймер
фаєрить часто (2 хв); якщо попередній ран ще працює — лок не дасть накластися.

Стани рядка: claim_next() ставить IN_PROGRESS з орендою worker_lease_seconds. HTTP 200 →
DONE з тілом відповіді (його читає веб-форма через /queue/status). HTTP 4xx → ERROR
одразу (детерміновано: офенса нема, поганий запит). HTTP 5xx / таймаут → рядок лишаємо
IN_PROGRESS: оренда спливе — claim забере знову; після worker_max_attempts → ERROR.
Немає з'єднання з мідлварем ≥3 рази за ран → зупиняємось, не молотимо даремно.
"""

import fcntl
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

import queue_db

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
LOG_FILE = os.path.join(BASE_DIR, "worker.log")
LOCK_FILE = os.path.join(BASE_DIR, "worker.lock")
DB_PATH = os.path.join(BASE_DIR, "ai_state.db")
PROCESS_URL = "http://127.0.0.1:5000/process-one"
MAX_CONN_ERRORS = 3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)

with open(CONFIG_FILE, "r", encoding="utf-8") as f:
    config = json.load(f)

# Конкурентність = кількості воркерів gunicorn: більше лише створить чергу всередині
# сервісу і зайвий тиск на Ariel (переміряно 2026-08-28 на поллері: 3 → 5 виграшу не дало).
CONCURRENCY = int(config.get("worker_concurrency", 3))
LEASE_SECONDS = float(config.get("worker_lease_seconds", 900))
MAX_ATTEMPTS = int(config.get("worker_max_attempts", 3))
BATCH_PER_RUN = int(config.get("worker_batch_per_run", 0))  # 0 = до порожньої черги
SWEEP_LOW_MAG_MAX = int(config.get("queue_sweep_low_mag_max", 3))
SWEEP_TTL_DAYS = float(config.get("queue_sweep_ttl_days", 3))
DONE_RETENTION_DAYS = float(config.get("queue_done_retention_days", 14))
ALERT_DEPTH = int(config.get("queue_alert_depth", 1500))
HTTP_TIMEOUT = float(config.get("timeout_seconds", 600)) + 30  # трохи більше за таймаут самого аналізу


def process_claim(claim: dict) -> str:
    """Один офенс → /process-one. Повертає код результату для лічильників. Виняток не
    піднімає: один невдалий офенс не має валити ран."""
    off_id = claim["offense_id"]
    body = {"offense_id": off_id, "is_manual": claim["source"] == "manual", **(claim.get("overrides") or {})}
    tag = f"{off_id} [m{claim['magnitude']} {claim['source']} #{claim['attempts']}]"
    try:
        r = requests.post(PROCESS_URL, json=body, timeout=HTTP_TIMEOUT)
    except requests.exceptions.ConnectionError as e:
        logging.error(f"❌ {tag}: немає з'єднання з мідлварем: {e}")
        return "conn"
    except requests.exceptions.Timeout:
        logging.error(f"⏳ {tag}: таймаут {HTTP_TIMEOUT:.0f} с — рядок лишається IN_PROGRESS до спливу оренди.")
        return "timeout"
    except Exception as e:
        logging.error(f"❌ {tag}: {e}")
        return "err"

    with queue_db.connect(DB_PATH) as conn:
        if r.status_code == 200:
            try:
                res = r.json()
            except ValueError:
                res = {"status": "ok", "raw": r.text[:500]}
            body_status = res.get("status", "ok") if isinstance(res, dict) else "ok"
            message = str(res.get("message", "")) if isinstance(res, dict) else ""

            # HTTP 200 + status "error" = аналіз НЕ відбувся (AQL 422/ERROR/таймаут Ariel,
            # обидва AI-провайдери впали). В offenses це AQL_ERROR/AI_ERROR ≠ PROCESSED,
            # тобто офенс лишився відкритим і потребує повтору — але не миттєвого (Ariel
            # впаде так само) і не вічного (старий поллер молотив такі кожні 10 хв 48 год).
            # Ставимо ERROR: поллер force-перекладе рядок у чергу через
            # queue_error_retry_hours, «щойно AQL виправлено» — а в /queue/depth це видно.
            if body_status == "error":
                queue_db.mark(conn, off_id, queue_db.ERROR, res)
                logging.warning(f"⚠️ {tag} → error: {message[:160]} — ERROR, повтор поллером через retry_hours.")
                return "app_error"

            # «Currently processing» — той самий офенс зараз крутить інший запит (напр.
            # ручний). Не позначаємо нічого: рядок лишається IN_PROGRESS, оренда спливе —
            # claim повернеться. Це природний backoff замість busy-loop на /process-one.
            if body_status == "skipped" and "processing" in message.lower():
                logging.info(f"⏳ {tag} → {message} — лишаємо IN_PROGRESS до спливу оренди.")
                return "busy"

            queue_db.mark(conn, off_id, queue_db.DONE, res)
            score = f" score {res['score']}" if isinstance(res, dict) and "score" in res else ""
            logging.info(f"✅ {tag} → {body_status}{score}")
            return "ok"
        if 400 <= r.status_code < 500:
            queue_db.mark(conn, off_id, queue_db.ERROR, {"http": r.status_code, "body": r.text[:500]})
            logging.error(f"❌ {tag}: HTTP {r.status_code} — ERROR (не повторюємо).")
            return "http4xx"
        if claim["attempts"] >= MAX_ATTEMPTS:
            queue_db.mark(conn, off_id, queue_db.ERROR, {"http": r.status_code, "body": r.text[:500]})
            logging.error(f"❌ {tag}: HTTP {r.status_code}, спроб {claim['attempts']} ≥ {MAX_ATTEMPTS} — ERROR.")
            return "http5xx_final"
        logging.error(f"❌ {tag}: HTTP {r.status_code} — лишаємо IN_PROGRESS, повтор після спливу оренди.")
        return "http5xx"


def main() -> None:
    lock_handle = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logging.warning("⚠️ Попередній екземпляр воркера ще працює. Новий запуск скасовано.")
        sys.exit(0)

    logging.info(f"--- Запуск Worker (конкурентність {CONCURRENCY}) ---")
    started = time.time()

    with queue_db.connect(DB_PATH) as conn:
        dropped, purged = queue_db.sweep(conn, SWEEP_LOW_MAG_MAX, SWEEP_TTL_DAYS, DONE_RETENTION_DAYS)
        if dropped or purged:
            logging.info(f"🧹 Sweep: дропнуто QUEUED mag≤{SWEEP_LOW_MAG_MAX} старших за {SWEEP_TTL_DAYS:g} дн — {dropped}; "
                         f"вичищено DONE/ERROR старших за {DONE_RETENTION_DAYS:g} дн — {purged}.")
        d = queue_db.depth(conn)
    by_mag = " ".join(f"m{m}:{c}" for m, c in d["by_magnitude"].items())
    logging.info(f"📏 Глибина на старті: QUEUED {d['QUEUED']} ({by_mag}) · IN_PROGRESS {d['IN_PROGRESS']}")
    if d["QUEUED"] >= ALERT_DEPTH:
        logging.warning(f"🚨 Черга {d['QUEUED']} ≥ queue_alert_depth {ALERT_DEPTH}: дренаж не встигає за припливом.")

    counts: dict[str, int] = {}
    conn_errors = 0
    taken = 0
    stop = False

    def claim_one():
        with queue_db.connect(DB_PATH) as c:
            return queue_db.claim_next(c, LEASE_SECONDS)

    hold_logged = [False]

    def wait_for_chat_hold():
        """Пісочниця (/chat) поставила hold → не беремо НОВИХ офенсів, поки він активний:
        ті, що вже в /process-one, дороблюються, і наступний слот llm01 дістається людині.
        Hold має дедлайн (chat_hold_seconds / chat_grace_seconds), тож чекання скінченне."""
        while not stop:
            with queue_db.connect(DB_PATH) as c:
                until = queue_db.hold_until(c, "chat")
                active = queue_db.hold_active(c, "chat")
            if not active:
                if hold_logged[0]:
                    hold_logged[0] = False
                    logging.info("▶️ Пісочниця звільнила llm01 — продовжуємо дренаж.")
                return
            if not hold_logged[0]:
                hold_logged[0] = True
                logging.info(f"⏸ Пісочниця активна (hold до {until} UTC) — нових офенсів не беремо, поточні дороблюємо.")
            time.sleep(2)

    # Кожен потік сам claim'ить наступний рядок і обробляє його — так найважчі офенси не
    # блокують ті, що вже готові, а порядок claim'у гарантує БД, не пул.
    def loop():
        nonlocal conn_errors, taken, stop
        while not stop:
            if BATCH_PER_RUN and taken >= BATCH_PER_RUN:
                return
            wait_for_chat_hold()
            if stop:
                return
            claim = claim_one()
            if claim is None:
                return
            taken += 1
            outcome = process_claim(claim)
            counts[outcome] = counts.get(outcome, 0) + 1
            if outcome == "conn":
                conn_errors += 1
                if conn_errors >= MAX_CONN_ERRORS:
                    stop = True
                    logging.error(f"🛑 Мідлваре недоступне ({conn_errors} відмов з'єднання). Зупиняємо ран; "
                                  f"оренда поверне рядки в чергу.")

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        for _ in range(CONCURRENCY):
            pool.submit(loop)

    with queue_db.connect(DB_PATH) as conn:
        d = queue_db.depth(conn)
    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "нічого"
    logging.info(f"Оброблено {taken} за {time.time() - started:.0f} с: {summary}. "
                 f"Лишилось QUEUED {d['QUEUED']} · IN_PROGRESS {d['IN_PROGRESS']} · ERROR {d['ERROR']}.")
    logging.info("--- Завершення ---\n")


if __name__ == "__main__":
    main()
