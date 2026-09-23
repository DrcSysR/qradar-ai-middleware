import requests
import json
import time
import os
import urllib3
import logging
import fcntl
import sys
import sqlite3

from prompts_loader import get_rule_keys, matched_rule_key
import queue_db

# --- НАЛАШТУВАННЯ ---
LOOKBACK_TIME_MS = 48 * 60 * 60 * 1000  # 48 годин: страховка, щоб офенси, пропущені під час бурсту, не гинули поза вікном (deep/manual режим бере 7 днів через AQL time_depth)
# Стеля лише на НОВІ рядки за ран: кожен новий офенс коштує один has_ai_note API-виклик.
# Перший ран після деплою бачить усе 48-год вікно (~2.5k) — розкладаємо на кілька ранів.
MAX_ENQUEUE_PER_RUN = 1500
LOG_FILE = "/opt/qradar-middleware/poller.log"
LOCK_FILE = "/opt/qradar-middleware/poller.lock"
DB_PATH = "/opt/qradar-middleware/ai_state.db"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
PROMPTS_FILE = os.path.join(BASE_DIR, "prompts.json")

with open(CONFIG_FILE, "r", encoding="utf-8") as f:
    config = json.load(f)
QRADAR_API = f"{config['qradar_url']}/api"
HEADERS = {"SEC": config["qradar_token"], "Accept": "application/json"}
# ERROR-рядок черги (AQL/AI впали в /process-one) перекладаємо назад у QUEUED не раніше,
# ніж через стільки годин: Ariel за хвилину не одужає, а AQL-файл лагодиться деплоєм.
# Раніше поллер молотив AQL_ERROR кожні 10 хв усі 48 год — це і є та «зациклена трійка».
ERROR_RETRY_HOURS = float(config.get("queue_error_retry_hours", 6))

target_rules = get_rule_keys(PROMPTS_FILE)


def age_hours(ts_utc: str) -> float:
    """Вік рядка черги за enqueued_at (UTC 'YYYY-MM-DD HH:MM:SS', як пише queue_db)."""
    import calendar
    try:
        return (time.time() - calendar.timegm(time.strptime(ts_utc, "%Y-%m-%d %H:%M:%S"))) / 3600
    except (TypeError, ValueError):
        return 0.0

# --- ФУНКЦІЇ БАЗИ ДАНИХ ТА API ---
def is_processed_in_db(offense_id):
    """Перевіряє в SQLite, чи вже був цей офенс успішно оброблений"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM offenses WHERE offense_id = ?", (offense_id,))
            row = cursor.fetchone()
            return row is not None and row[0] == 'PROCESSED'
    except sqlite3.OperationalError:
        return False

def get_rules_map():
    """id->name для всіх правил радара. Потрібно, щоб матчити офенс за НАЗВОЮ
    правила-учасника, а не лише за описом (опис часто = ім'я події, напр. 'Traffic End')."""
    try:
        r = requests.get(f"{QRADAR_API}/analytics/rules?fields=id,name", headers=HEADERS, verify=False, timeout=30)
        if r.status_code == 200:
            return {item["id"]: item.get("name", "") for item in r.json()}
        logging.warning(f"Не вдалося завантажити мапу правил: HTTP {r.status_code}")
    except Exception as e:
        logging.warning(f"Помилка завантаження мапи правил: {e}")
    return {}

def has_ai_note(offense_id):
    url = f"{QRADAR_API}/siem/offenses/{offense_id}/notes"
    try:
        response = requests.get(url, headers=HEADERS, verify=False, timeout=5)
        if response.status_code == 200:
            notes = response.json()
            return any("AI Analysis" in note.get("note_text", "") for note in notes)
    except Exception:
        return False
    return False

# --- ПЕРЕВІРКА НА ЗАПУЩЕНИЙ ЕКЗЕМПЛЯР ---
lock_file_handle = open(LOCK_FILE, "w")
try:
    fcntl.flock(lock_file_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
except IOError:
    logging.warning("⚠️ Попередній екземпляр пулера ще працює. Новий запуск скасовано.")
    sys.exit(0)

# --- ВИКОНАННЯ ---
logging.info("--- Запуск Poller (продюсер черги) ---")

search_start_time = int(time.time() * 1000) - LOOKBACK_TIME_MS

logging.info(f"Шукаємо офенси за останні 48 годин (з {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(search_start_time/1000))})")

# Запитуємо тільки відкриті інциденти, створені після search_start_time
# fields=...,rules — потрібні назви правил-учасників для матчингу за іменем правила
# fields=...,magnitude — ключ пріоритету в черзі (work_queue), див. queue_db.ORDER_BY
# fields=...,offense_source — офенс без джерела (null) = «напівнароджений» під час збою
# магістрату: INOFFENSE() на нього дає FunctionCreateError 28523, аналізувати нічого
url = f"{QRADAR_API}/siem/offenses?fields=id,description,rules,start_time,magnitude,offense_source&filter=status%3D%22OPEN%22%20and%20start_time%3E{search_start_time}"

rules_map = get_rules_map()

try:
    response = requests.get(url, headers=HEADERS, verify=False, timeout=10)
    if response.status_code == 200:
        offenses = response.json()
        logging.info(f"Знайдено офенсів у вікні пошуку: {len(offenses)}")

        # --- Поллер = ПРОДЮСЕР. Нічого не обробляє, лише кладе в чергу. ---
        #
        # Було (до 23.09.2026): поллер сам відбирав ≤100 офенсів на ран (кругова роздача
        # по юзкейсах, усередині — найстаріші вперед) і слав їх у /universal-analysis.
        # Магнітуда в цьому порядку не брала участі взагалі. Замір 23.09.2026: 150 зі 158
        # відкритих injection-офенсів (51 на mag 7) мідлваре не бачило жодного разу —
        # вони конкурували за 100 місць із File Decode/IRC/Botnet і програвали.
        #
        # Стало: кожен зматчений офенс іде рядком у work_queue з його магнітудою; порядок
        # обробки (magnitude DESC → manual → найстаріші) задає worker.py при claim'і.
        # Ліміту «100 на ран» більше немає — черга сама вирівнює навантаження.
        #
        # has_ai_note — це API-виклик на офенс, тож робимо його ЛИШЕ для офенсів, яких у
        # черзі ще немає (перший раз бачимо). Рядок у черзі = has_ai_note вже пройдено.
        counts = {"inserted": 0, "refreshed": 0, "requeued": 0, "skipped": 0}
        skipped_noted = 0
        skipped_processed = 0
        skipped_damaged = 0
        unmatched = 0
        hit_limit = False
        per_lens = {}

        with queue_db.connect(DB_PATH) as qconn:
            for off in offenses:
                off_id = int(off["id"])
                desc = off.get("description", "")
                rule_names = [rules_map.get(r.get("id"), "") for r in off.get("rules", [])]

                # 0. Пошкоджений офенс: offense_source = null. Такі народжуються, коли кореляція
                #    працює, а персистер магістрату стоїть (інцидент 23.09.2026: 1154 шт. за 4 год).
                #    В API вони OPEN з магнітудою, але без джерела й event-мапінгу — INOFFENSE(id)
                #    падає з FunctionCreateError 28523, тож жодна лінза їх не проаналізує. Не
                #    кладемо в чергу взагалі: інакше воркер палить AQL у 422, а ERROR-requeue
                #    повторює це кожні 6 год. Самі не «долічуються» (0 з 101 за 40 хв).
                if off.get("offense_source") in (None, ""):
                    skipped_damaged += 1
                    continue

                # 1. Матчинг за описом офенсу АБО назвою правила-учасника (дешево, локально)
                key = matched_rule_key(target_rules, desc, rule_names)
                if key is None:
                    unmatched += 1
                    continue

                # 2. Швидка перевірка по базі даних
                if is_processed_in_db(off_id):
                    skipped_processed += 1
                    continue

                # 3. Надійна перевірка через API — лише для нових у черзі (якщо в QRadar
                #    вже є нотатка, але БД була видалена)
                q_status = queue_db.get_status(qconn, off_id)
                force = False
                if q_status is None:
                    if counts["inserted"] >= MAX_ENQUEUE_PER_RUN:
                        hit_limit = True
                        continue
                    if has_ai_note(off_id):
                        skipped_noted += 1
                        continue
                elif q_status == queue_db.ERROR:
                    # 4. ERROR (AQL/AI впали) і офенс досі OPEN → повтор, але не частіше
                    #    ніж раз на ERROR_RETRY_HOURS. Молодший ERROR лишаємо як є.
                    row = queue_db.status_of(qconn, off_id) or {}
                    force = age_hours(row.get("enqueued_at", "")) >= ERROR_RETRY_HOURS

                outcome = queue_db.enqueue(qconn, off_id, int(off.get("magnitude") or 0), "auto", key, force=force)
                counts[outcome] = counts.get(outcome, 0) + 1
                if outcome == "inserted":
                    per_lens[key] = per_lens.get(key, 0) + 1

            d = queue_db.depth(qconn)

        logging.info(
            f"📥 У чергу: нових {counts['inserted']}, оновлено магнітуду {counts['refreshed']}, "
            f"повторно після ERROR {counts['requeued']}, без змін {counts['skipped']} · "
            f"пропущено: PROCESSED {skipped_processed}, пошкоджені (source=null) {skipped_damaged}, "
            f"з нотаткою AI {skipped_noted}, без юзкейсу {unmatched}."
        )
        if per_lens:
            top = sorted(per_lens.items(), key=lambda kv: -kv[1])[:8]
            logging.info("📊 Нові за юзкейсами (топ-8): " + ", ".join(f"{k[:28]} {v}" for k, v in top))
        if hit_limit:
            logging.info(f"⚠️ Досягнуто стелю нових за ран ({MAX_ENQUEUE_PER_RUN}) — решта наступного разу.")
        by_mag = " ".join(f"m{m}:{c}" for m, c in d["by_magnitude"].items())
        logging.info(
            f"📏 Глибина черги: QUEUED {d['QUEUED']} ({by_mag}) · IN_PROGRESS {d['IN_PROGRESS']} · "
            f"DONE {d['DONE']} · ERROR {d['ERROR']}"
        )

    else:
        logging.error(f"Помилка API QRadar: {response.status_code}")
except Exception as e:
    logging.error(f"Критична помилка: {e}")

logging.info("--- Завершення ---\n")
