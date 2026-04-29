import requests
import json
import time
import os
import urllib3
import logging
import fcntl
import sys
import sqlite3

from prompts_loader import get_rule_keys

# --- НАЛАШТУВАННЯ ---
LOOKBACK_TIME_MS = 14 * 24 * 60 * 60 * 1000  # 14 днів у мілісекундах
MAX_OFFENSES_PER_RUN = 50
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

logging.info(f"Шукаємо офенси за останні 14 днів (з {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(search_start_time/1000))})")

# Запитуємо тільки відкриті інциденти, створені після search_start_time
url = f"{QRADAR_API}/siem/offenses?filter=status%3D%22OPEN%22%20and%20start_time%3E{search_start_time}"

try:
    response = requests.get(url, headers=HEADERS, verify=False, timeout=10)
    if response.status_code == 200:
        offenses = response.json()
        logging.info(f"Знайдено офенсів у вікні пошуку: {len(offenses)}")
        
        processed_count = 0
        hit_limit = False
        consecutive_conn_errors = 0
        MAX_CONSECUTIVE_CONN_ERRORS = 3  # Якщо middleware не відповідає N разів поспіль — припиняємо цикл, наступний фаєр спробує знову

        for off in offenses:
            if processed_count >= MAX_OFFENSES_PER_RUN:
                logging.info(f"⚠️ Досягнуто ліміт ({MAX_OFFENSES_PER_RUN}).")
                hit_limit = True
                break

            off_id = int(off["id"])
            desc = off.get("description", "")

            # 1. Швидка перевірка по базі даних
            if is_processed_in_db(off_id):
                continue

            # 2. Перевірка назви правила
            if any(rule.lower() in desc.lower() for rule in target_rules):

                # 3. Надійна перевірка через API (якщо в QRadar вже є нотатка, але БД була видалена)
                if not has_ai_note(off_id):
                    logging.info(f"[+] Новий офенс: {off_id}. Відправка на AI...")
                    try:
                        ai_resp = requests.post(MIDDLEWARE_URL, json={"offense_id": off_id, "is_manual": False}, timeout=600)
                        if ai_resp.status_code == 200:
                            logging.info(f"✅ Офенс {off_id} успішно оброблено. Middleware зберіг статус у БД.")
                        else:
                            logging.error(f"❌ Помилка Middleware: {ai_resp.status_code}")

                        processed_count += 1
                        consecutive_conn_errors = 0
                    except requests.exceptions.Timeout:
                        logging.error(f"⏳ Таймаут для {off_id}.")
                        processed_count += 1
                        consecutive_conn_errors = 0
                    except requests.exceptions.ConnectionError as e:
                        consecutive_conn_errors += 1
                        logging.error(f"❌ Connection refused для {off_id} (поспіль {consecutive_conn_errors}/{MAX_CONSECUTIVE_CONN_ERRORS}): {e}")
                        if consecutive_conn_errors >= MAX_CONSECUTIVE_CONN_ERRORS:
                            logging.error(f"🛑 Middleware недоступний {consecutive_conn_errors} разів поспіль. Припиняю цикл, наступний фаєр поллера спробує знову.")
                            break
                    except Exception as e:
                        logging.error(f"❌ Помилка з'єднання: {e}")
                        consecutive_conn_errors = 0
                else:
                    logging.info(f"ℹ️ Офенс {off_id} вже має нотатку від AI. Пропускаємо.")

        if not hit_limit and consecutive_conn_errors < MAX_CONSECUTIVE_CONN_ERRORS:
            logging.info("Черга порожня або повністю оброблена.")
            
    else:
        logging.error(f"Помилка API QRadar: {response.status_code}")
except Exception as e:
    logging.error(f"Критична помилка: {e}")

logging.info("--- Завершення ---\n")