import requests
import json
import time
import os
import urllib3
import logging
import fcntl
import sys

# --- НАЛАШТУВАННЯ ---
LOOKBACK_TIME_MS = 60 * 60 * 1000  # Шукаємо за останню 1 годину від минулого запуску
MAX_OFFENSES_PER_RUN = 5
LOG_FILE = "/opt/qradar-middleware/poller.log"
LOCK_FILE = "/opt/qradar-middleware/poller.lock"
PROCESSED_FILE = "/opt/qradar-middleware/processed_offenses.txt" # Файл пам'яті пулера

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
PROMPTS_FILE = os.path.join(BASE_DIR, "prompts.json")
STATE_FILE = os.path.join(BASE_DIR, "last_run_time.txt")
MIDDLEWARE_URL = "http://127.0.0.1:5000/universal-analysis"

with open(CONFIG_FILE, "r", encoding="utf-8") as f:
    config = json.load(f)
QRADAR_API = f"{config['qradar_url']}/api"
HEADERS = {"SEC": config["qradar_token"], "Accept": "application/json"}

with open(PROMPTS_FILE, "r", encoding="utf-8") as f:
    target_rules = [key for key in json.load(f).keys() if key != "Default"]

# --- ФУНКЦІЇ СТАНУ ТА ПАМ'ЯТІ ---
def get_last_run_time():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return int(f.read().strip())
    return int((time.time() - 3600) * 1000)

def set_last_run_time(timestamp):
    with open(STATE_FILE, "w") as f:
        f.write(str(timestamp))

def get_processed_offenses():
    """Зчитує ID інцидентів, які вже були проаналізовані"""
    if not os.path.exists(PROCESSED_FILE):
        return set()
    with open(PROCESSED_FILE, "r") as f:
        return set(line.strip() for line in f if line.strip())

def mark_as_processed(offense_id):
    """Записує ID у файл, щоб більше ніколи його не аналізувати"""
    with open(PROCESSED_FILE, "a") as f:
        f.write(f"{offense_id}\n")

def has_ai_note(offense_id):
    url = f"{QRADAR_API}/siem/offenses/{offense_id}/notes"
    try:
        response = requests.get(url, headers=HEADERS, verify=False, timeout=5)
        if response.status_code == 200:
            notes = response.json()
            # ВИПРАВЛЕНО: Шукаємо просто "AI Analysis", щоб ловити і (VERTEX), і (OLLAMA)
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
logging.info("--- Запуск Poller (Smart Queue Mode) ---")

last_run_raw = get_last_run_time()
search_start_time = last_run_raw - LOOKBACK_TIME_MS 
current_run_start = int(time.time() * 1000)
processed_local_cache = get_processed_offenses()

logging.info(f"Шукаємо офенси з: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(search_start_time/1000))}")

url = f"{QRADAR_API}/siem/offenses?filter=status%3D%22OPEN%22%20and%20start_time%3E{search_start_time}"

try:
    response = requests.get(url, headers=HEADERS, verify=False, timeout=10)
    if response.status_code == 200:
        offenses = response.json()
        logging.info(f"Знайдено офенсів у вікні пошуку: {len(offenses)}")
        
        processed_count = 0
        hit_limit = False
        
        for off in offenses:
            if processed_count >= MAX_OFFENSES_PER_RUN:
                logging.info(f"⚠️ Досягнуто ліміт ({MAX_OFFENSES_PER_RUN}). Оновлення часу відкладено.")
                hit_limit = True
                break

            off_id = str(off["id"])
            desc = off.get("description", "")
            
            # 1. Швидка перевірка по локальній пам'яті (без запиту до QRadar)
            if off_id in processed_local_cache:
                continue
            
            if any(rule.lower() in desc.lower() for rule in target_rules):
                # 2. Надійна перевірка через API (на випадок якщо локальний файл видалили)
                if not has_ai_note(off_id):
                    logging.info(f"[+] Новий офенс: {off_id}. Відправка на AI...")
                    try:
                        ai_resp = requests.post(MIDDLEWARE_URL, json={"offense_id": int(off_id), "is_manual": False}, timeout=600)
                        if ai_resp.status_code == 200:
                            logging.info(f"✅ Офенс {off_id} успішно оброблено.")
                            mark_as_processed(off_id) # Записуємо в пам'ять
                        else:
                            logging.error(f"❌ Помилка Middleware: {ai_resp.status_code}")
                        
                        processed_count += 1
                    except requests.exceptions.Timeout:
                        logging.error(f"⏳ Таймаут для {off_id}.")
                        processed_count += 1
                    except Exception as e:
                        logging.error(f"❌ Помилка з'єднання: {e}")
                else:
                    # Якщо нотатка є в QRadar, але немає в локальному файлі - синхронізуємо
                    mark_as_processed(off_id)
        
        if not hit_limit:
            logging.info("Черга порожня або оброблена. Оновлюємо час останнього запуску.")
            set_last_run_time(current_run_start)
            
    else:
        logging.error(f"Помилка API QRadar: {response.status_code}")
except Exception as e:
    logging.error(f"Критична помилка: {e}")

logging.info("--- Завершення ---\n")
