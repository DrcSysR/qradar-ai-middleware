import requests
import json
import time
import os
import urllib3
import logging
import fcntl
import sys
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed

from prompts_loader import get_rule_keys, matched_rule_key

# --- НАЛАШТУВАННЯ ---
LOOKBACK_TIME_MS = 48 * 60 * 60 * 1000  # 48 годин: страховка, щоб офенси, пропущені під час бурсту, не гинули поза вікном (deep/manual режим бере 7 днів через AQL time_depth)
MAX_OFFENSES_PER_RUN = 100  # стеля на ран; таймер рахує від завершення, fcntl-лок не дасть накластися
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
MIDDLEWARE_URL = "http://127.0.0.1:5000/universal-analysis"

with open(CONFIG_FILE, "r", encoding="utf-8") as f:
    config = json.load(f)
# Конкурентність = кількості воркерів gunicorn (3). Більше не прискорить: запити
# просто стануть у чергу всередині сервісу, зате Ariel отримає зайвий тиск.
POLLER_CONCURRENCY = int(config.get("poller_concurrency", 3))
QRADAR_API = f"{config['qradar_url']}/api"
HEADERS = {"SEC": config["qradar_token"], "Accept": "application/json"}

target_rules = get_rule_keys(PROMPTS_FILE)

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
logging.info("--- Запуск Poller (Smart DB Mode) ---")

search_start_time = int(time.time() * 1000) - LOOKBACK_TIME_MS

logging.info(f"Шукаємо офенси за останні 24 години (з {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(search_start_time/1000))})")

# Запитуємо тільки відкриті інциденти, створені після search_start_time
# fields=...,rules — потрібні назви правил-учасників для матчингу за іменем правила
# fields=...,start_time — потрібен для сортування «найстаріші вперед» усередині юзкейсу
url = f"{QRADAR_API}/siem/offenses?fields=id,description,rules,start_time&filter=status%3D%22OPEN%22%20and%20start_time%3E{search_start_time}"

rules_map = get_rules_map()

try:
    response = requests.get(url, headers=HEADERS, verify=False, timeout=10)
    if response.status_code == 200:
        offenses = response.json()
        logging.info(f"Знайдено офенсів у вікні пошуку: {len(offenses)}")
        
        processed_count = 0
        hit_limit = False
        consecutive_conn_errors = 0
        MAX_CONSECUTIVE_CONN_ERRORS = 3  # Якщо middleware не відповідає N разів поспіль — припиняємо цикл, наступний фаєр спробує знову

        # --- Відбір кандидатів: квота рану по юзкейсах ---
        #
        # Було: «перші MAX_OFFENSES_PER_RUN, що зматчились». QRadar віддає офенси
        # НАЙНОВІШИМИ ВПЕРЕД, тож при насиченні це LIFO — поллер щоразу перемелює голову
        # списку, а хвіст доживає до краю 48-год вікна й гине нерозібраним. Виміряно
        # 27.08.2026: 847 офенсів у вікні, ліміт вибирався за 8 с на позиції 101, а перший
        # офенс юзкейсу «Endpoint Administration» стояв на позиції 162 — тобто 125 офенсів
        # цього типу не могли потрапити в обробку в принципі, скільки б ранів не пройшло.
        # Один генератор обсягу (rogue-IP bruteforce) забирав 34 місця зі 100.
        #
        # Стало, два правила:
        #   1) КРУГОВА РОЗДАЧА по юзкейсах — беремо по одному офенсу з кожного зматченого
        #      ключа по колу. Жоден гучний юзкейс не з'їдає ран; фіксованої квоти на ключ
        #      не задаємо — частка сама масштабується від кількості присутніх юзкейсів.
        #   2) УСЕРЕДИНІ ЮЗКЕЙСУ — НАЙСТАРІШІ ВПЕРЕД. 48-год вікно це дедлайн, а не
        #      уподобання: свіжий офенс буде у вікні й наступного рану, старий — ні.
        #      Тому черга сортується за наближенням до вильоту з вікна.
        #
        # has_ai_note — це API-виклик на офенс, тому робимо його ЛИШЕ на момент, коли
        # офенс реально беруть у ран (як і раніше), а не на всі 800 кандидатів.
        buckets = {}
        for off in offenses:
            off_id = int(off["id"])
            desc = off.get("description", "")
            rule_names = [rules_map.get(r.get("id"), "") for r in off.get("rules", [])]

            # 1. Швидка перевірка по базі даних
            if is_processed_in_db(off_id):
                continue

            # 2. Матчинг за описом офенсу АБО назвою правила-учасника
            key = matched_rule_key(target_rules, desc, rule_names)
            if key is None:
                continue
            buckets.setdefault(key, []).append((off.get("start_time") or 0, off_id))

        for key in buckets:
            buckets[key].sort()  # найстаріші вперед: у них найменше часу до вильоту з вікна

        candidates = []
        skipped_noted = 0
        # Порядок обходу — від найбільшого юзкейсу до найменшого, лише щоб він був
        # детермінований; на саму частку це не впливає, роздача все одно кругова.
        order = sorted(buckets, key=lambda k: (-len(buckets[k]), k))
        pos = {k: 0 for k in buckets}
        taken = {k: 0 for k in buckets}

        while len(candidates) < MAX_OFFENSES_PER_RUN:
            took_any = False
            for key in order:
                if len(candidates) >= MAX_OFFENSES_PER_RUN:
                    break
                lst = buckets[key]
                i = pos[key]
                while i < len(lst):
                    off_id = lst[i][1]
                    i += 1
                    # 3. Надійна перевірка через API (якщо в QRadar вже є нотатка, але БД була видалена)
                    if has_ai_note(off_id):
                        skipped_noted += 1
                        continue
                    candidates.append(off_id)
                    taken[key] += 1
                    took_any = True
                    break
                pos[key] = i
            if not took_any:
                break  # усі черги вичерпані

        if skipped_noted:
            logging.info(f"ℹ️ Пропущено {skipped_noted} офенсів — уже мають нотатку від AI.")
        if len(candidates) >= MAX_OFFENSES_PER_RUN:
            hit_limit = True
            logging.info(f"⚠️ Досягнуто ліміт ({MAX_OFFENSES_PER_RUN}).")
        if buckets:
            shape = ", ".join(f"{k[:28]} {taken[k]}/{len(buckets[k])}" for k in order[:8])
            logging.info(f"📊 Квота рану (взято/у вікні), топ-8 юзкейсів: {shape}")

        # --- Обробка: паралельно ---
        # Раніше офенси йшли строго по одному, і ран упирався в час інференсу: ~30 с на офенс
        # = 120/год при ~200 нових/год, черга росла (1523 → 1712 за ранок 25.08). При цьому
        # gunicorn має 3 воркери й уже їх чергував — використовувалась третина потужності.
        # Конкурентність тримаємо на рівні кількості воркерів: більше не прискорить, лише
        # створить чергу всередині gunicorn і зайве навантаження на Ariel.
        if candidates:
            logging.info(f"До обробки: {len(candidates)} офенсів, конкурентність {POLLER_CONCURRENCY}.")

        conn_errors = 0

        def process_one(off_id):
            """Повертає ('ok'|'timeout'|'conn'|'err', off_id). Виняток не піднімає:
            один невдалий офенс не має валити ран."""
            try:
                ai_resp = requests.post(MIDDLEWARE_URL, json={"offense_id": off_id, "is_manual": False}, timeout=600)
                if ai_resp.status_code == 200:
                    logging.info(f"✅ Офенс {off_id} успішно оброблено. Middleware зберіг статус у БД.")
                else:
                    logging.error(f"❌ Помилка Middleware для {off_id}: {ai_resp.status_code}")
                return "ok", off_id
            except requests.exceptions.Timeout:
                logging.error(f"⏳ Таймаут для {off_id}.")
                return "timeout", off_id
            except requests.exceptions.ConnectionError as e:
                logging.error(f"❌ Connection refused для {off_id}: {e}")
                return "conn", off_id
            except Exception as e:
                logging.error(f"❌ Помилка з'єднання для {off_id}: {e}")
                return "err", off_id

        with ThreadPoolExecutor(max_workers=POLLER_CONCURRENCY) as pool:
            futures = {pool.submit(process_one, oid): oid for oid in candidates}
            for fut in as_completed(futures):
                outcome, off_id = fut.result()
                if outcome in ("ok", "timeout"):
                    processed_count += 1
                elif outcome == "conn":
                    conn_errors += 1
        # «Поспіль» при паралельній відправці не має сенсу — рахуємо загальну кількість
        # відмов з'єднання за ран. Той самий намір: мідлваре лежить → не молотимо даремно.
        if conn_errors >= MAX_CONSECUTIVE_CONN_ERRORS:
            logging.error(f"🛑 Middleware недоступний ({conn_errors} відмов з'єднання за ран). Наступний фаєр поллера спробує знову.")
            consecutive_conn_errors = conn_errors

        if not hit_limit and consecutive_conn_errors < MAX_CONSECUTIVE_CONN_ERRORS:
            logging.info("Черга порожня або повністю оброблена.")
            
    else:
        logging.error(f"Помилка API QRadar: {response.status_code}")
except Exception as e:
    logging.error(f"Критична помилка: {e}")

logging.info("--- Завершення ---\n")