from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from google.oauth2 import service_account
import google.auth.transport.requests
import httpx
import asyncio
import urllib.parse
import logging
import json
import re
import os
import sqlite3
import time

from prompts_loader import get_dynamic_prompt as _get_dynamic_prompt
from prompts_loader import get_matched_lenses
import config_schema

VERTEX_KEY_PATH = "/opt/qradar-middleware/me-vertex-ai-studio-666353d9e1df.json"
CONFIG_FILE = "/opt/qradar-middleware/config.json"
PROMPTS_FILE = "/opt/qradar-middleware/prompts.json"
PROMPTS_DIR = "/opt/qradar-middleware/prompts"
QUERIES_DIR = "/opt/qradar-middleware/queries"
DB_PATH = "/opt/qradar-middleware/ai_state.db"

MODELS_MAX_CTX = {
    "qwen2.5-coder:7b": 32768,
    "qwen2.5-coder:14b": 32768,
    "qwen2.5-coder:32b": 32768,
    "qwen3.5:9b": 65536,
    "qwen3.5:27b": 65536,
    # llm01 (llama.cpp, OpenAI /v1) — сервер піднято з ctx 8192 (2 GB VRAM, більший KV-кеш не влазить).
    # Тримаємо тут 8192, інакше max_chars ріже промпт під 32k і переповнює контекст → падіння якості.
    "qwen2.5-coder-3b": 8192,
    "qwen2.5-coder-7b": 8192,
}
MODELS_WITH_JSON_FORMAT = {"qwen2.5-coder:7b", "qwen2.5-coder:14b", "qwen2.5-coder:32b"}

# Кеш inverse-індексу reference sets (ip -> [setnames]). Скидається тільки рестартом сервісу.
REFSET_CACHE = {"index": None, "ts": 0.0}
RULES_MAP_CACHE = {"map": None, "ts": 0.0}
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# --- ЗАВАНТАЖЕННЯ КОНФІГУРАЦІЇ ---
def load_config():
    # Читання + валідація за реєстром у config_schema.py: невідомий ключ (одруківка)
    # і невірний тип більше не проходять мовчки, а лишають слід у лозі. Дефолти НЕ
    # підмішуються — повертається рівно вміст файлу, тож усі виклики .get(key, default)
    # нижче по коду поводяться точно як раніше.
    return config_schema.load(CONFIG_FILE)

APP_CONFIG = load_config()

# --- НАЛАШТУВАННЯ ЛОГУВАННЯ (DEBUG / NORMAL) ---
DEBUG_MODE = APP_CONFIG.get("debug_mode", False)
LOG_LEVEL = logging.DEBUG if DEBUG_MODE else logging.INFO

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
# Під gunicorn кореневий логер уже має хендлери, і basicConfig() у такому разі МОВЧКИ
# нічого не робить — рівень лишається WARNING. Через це в journalctl не було жодного
# INFO: ні "Офенс оброблено", ні авто-закриття, ні ескалацій, і сервіс виглядав мертвим,
# хоча працював. Рівень треба виставити явно; хендлери gunicorn лишаємо його ж.
logging.getLogger().setLevel(LOG_LEVEL)

if not DEBUG_MODE:
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
# -----------------------------------------------

# Динамічні глобальні змінні
QRADAR_API_URL = f"{APP_CONFIG['qradar_url']}/api"
# .get(), а не індекс: Ollama з інфраструктури виведена (2026-08-08, лишились
# Qwen-3B на llama.cpp + Vertex), і ключа в config.json більше немає. Прямий індекс
# тут клав би сервіс на старті з KeyError, хоча провайдер навіть не використовується.
OLLAMA_API_URL = f"{APP_CONFIG.get('ollama_url', 'http://127.0.0.1:11434')}/api/generate"
HEADERS = {
    "SEC": APP_CONFIG['qradar_token'],
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# --- ЗАПОБІЖНИК: вердикт «компрометація» не може автозакритись ---
# Промпти прямо забороняють ставити mitigated:true разом з вердиктом про успішну
# компрометацію, але модель це правило регулярно ігнорує: офенси 1188072, 1189958,
# 1189968 (GP_Plain_User_Successful_Compromise, score 0.9) і 1173288
# (Active_Lateral_Movement_Compromised_Admin, score 0.9) закрились самі з
# mitigated:true. Найгірший сценарій — низький скор при такому вердикті: тоді офенс
# не лише закриється, а ще й зніме IP з блок-листа. Тому правило дублюємо в коді:
# сказав «компрометація» — офенс лишається відкритим і йде на аналітика.
COMPROMISE_VERDICT_RE = re.compile(
    r"compromis|lateral[ _-]?movement|account[ _-]?takeover|successful[ _-]?(?:intrusion|breach)",
    re.IGNORECASE,
)
# Заперечення ('No_Compromise', 'Not_Compromised', 'FP — no compromise') під запобіжник
# не підпадають, інакше він спрацьовував би на нормальних benign-вердиктах.
# Межа слова тут НЕ \b: вердикти пишуться в snake_case, а `_` — символ слова, тож
# у 'Host_Not_Compromised' перед 'Not' межі немає і заперечення б не спрацювало.
NON_COMPROMISE_VERDICT_RE = re.compile(
    r"(?<![A-Za-z])(?:no|not|non|un|never|without)[ _-]*compromis"
    r"|false[ _-]?positive"
    r"|(?<![A-Za-z])fp(?![A-Za-z])",
    re.IGNORECASE,
)
COMPROMISE_SCORE_FLOOR = 0.9


def enforce_compromise_guard(verdict, score, mitigated):
    """Вердикт про компрометацію → mitigated знімаємо, score піднімаємо до порога ескалації.

    Повертає (score, mitigated, note). Порожній note = запобіжник не спрацював.
    """
    text = str(verdict or "")
    if not COMPROMISE_VERDICT_RE.search(text) or NON_COMPROMISE_VERDICT_RE.search(text):
        return score, mitigated, ""
    # Вердикт уже веде на аналітика — втручатись нема сенсу.
    if not mitigated and score > 0.6:
        return score, mitigated, ""
    new_score = max(score, COMPROMISE_SCORE_FLOOR)
    note = (
        f" | Guard: вердикт '{text}' = компрометація → mitigated знято"
        f"{f', score {score}→{new_score}' if new_score != score else ''}, офенс лишається відкритим"
    )
    return new_score, False, note


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        # WAL дозволяє паралельні читання + одне запис без "database is locked"
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS offenses (
                offense_id INTEGER PRIMARY KEY,
                status TEXT,
                score REAL,
                verdict TEXT,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Міграція: колонку escalated додано пізніше (каскадна тріаж), на проді таблиця вже існує.
        cols = {row[1] for row in conn.execute("PRAGMA table_info(offenses)")}
        if "escalated" not in cols:
            conn.execute("ALTER TABLE offenses ADD COLUMN escalated INTEGER DEFAULT 0")
init_db()

app = FastAPI(title="QRadar AI Middleware")

# Нова проста модель - приймаємо ТІЛЬКИ номер інциденту
class UniversalTrigger(BaseModel):
    offense_id: int
    is_manual: bool = False

def get_dynamic_prompt(rule_name, rule_names=None):
    return _get_dynamic_prompt(rule_name, PROMPTS_FILE, PROMPTS_DIR, rule_names=rule_names)


async def fetch_rules_map(client: httpx.AsyncClient) -> dict:
    url = f"{QRADAR_API_URL}/analytics/rules?fields=id,name"
    try:
        resp = await client.get(url, headers=HEADERS)
        if resp.status_code != 200:
            logging.warning(f"Rules map fetch failed: HTTP {resp.status_code}")
            return {}
        return {item["id"]: item.get("name", "") for item in resp.json()}
    except Exception as e:
        logging.warning(f"Rules map fetch error: {e}")
        return {}


async def get_rules_map(client: httpx.AsyncClient) -> dict:
    ttl = float(APP_CONFIG.get("rules_map_cache_ttl_seconds", 3600))
    now = time.time()
    if RULES_MAP_CACHE["map"] is None or (now - RULES_MAP_CACHE["ts"]) > ttl:
        RULES_MAP_CACHE["map"] = await fetch_rules_map(client)
        RULES_MAP_CACHE["ts"] = now
        logging.info(f"Rules map cache loaded: {len(RULES_MAP_CACHE['map'])} rules.")
    return RULES_MAP_CACHE["map"]



async def get_offense_details(client: httpx.AsyncClient, offense_id: int):
    url = f"{QRADAR_API_URL}/siem/offenses/{offense_id}"
    response = await client.get(url, headers=HEADERS)
    
    if response.status_code != 200:
        logging.error(f"Failed to fetch Offense {offense_id}")
        return None
        
    data = response.json()
    entity_value = data.get("offense_source", "Unknown")
    offense_type_id = data.get("offense_type", 0)
    offense_name = data.get("description", "Default")

    if offense_type_id == 0: entity_type = "SourceIP"
    elif offense_type_id == 1: entity_type = "DestinationIP"
    elif offense_type_id == 3: entity_type = "User"
    else: entity_type = "SourceIP"

    return {
        "entity_value": entity_value,
        "entity_type": entity_type,
        "offense_name": offense_name,
        "rules": data.get("rules", []),
        "start_time": data.get("start_time"),
        "last_updated_time": data.get("last_updated_time"),
    }

def _strip_aql_comments(aql: str) -> str:
    # QRadar Ariel НЕ підтримує `--` коментарі — парсер не розпізнає їх як коментар,
    # доходить до тексту (особливо не-ASCII) і падає 422 ParseError. Тож вирізаємо
    # `--`...кінець-рядка перед відправкою, але тільки поза лапками (щоб не зачепити
    # літерали типу '8.8--8.8', яких тут нема, але хай буде безпечно).
    out = []
    for line in aql.splitlines():
        in_s = in_d = False
        cut = None
        i = 0
        while i < len(line):
            c = line[i]
            if c == "'" and not in_d:
                in_s = not in_s
            elif c == '"' and not in_s:
                in_d = not in_d
            elif c == '-' and not in_s and not in_d and i + 1 < len(line) and line[i + 1] == '-':
                cut = i
                break
            i += 1
        out.append(line[:cut].rstrip() if cut is not None else line)
    return "\n".join(out)


async def _delete_ariel_search(client: httpx.AsyncClient, search_id: str) -> None:
    """Прибрати за собою пошук в Ariel. QRadar тримає завершені пошуки на диску, а мідлваре
    робить один пошук на офенс — при ~570 офенсах/год це ~13 тис. осиротілих пошуків на добу
    (міряно: 5202 у списку). DELETE на незавершеному пошуку ще й скасовує його виконання."""
    if not search_id:
        return
    try:
        await client.delete(f"{QRADAR_API_URL}/ariel/searches/{search_id}", headers=HEADERS)
    except Exception as e:
        logging.debug(f"Ariel search {search_id} cleanup failed: {e}")


async def fetch_events_multi_lens(client: httpx.AsyncClient, offense_id: int, time_depth: str,
                                  aql_files: list, entity_value: str = "", entity_type: str = "") -> tuple:
    """Виконати AQL кожної лінзи й склеїти події. Повертає (events, failed_aql_files).

    events = None лише коли впали ВСІ лінзи (тоді вище по стеку — AQL_ERROR і офенс
    лишається відкритим). Якщо впала частина — віддаємо те, що зібралось, а список
    failed сигналізує викликачу, що close_on_empty застосовувати вже не можна.
    Ключ `Lens` додається лише на композиті, щоб не з'їдати контекст llm01 даремно."""
    events, failed = [], []
    multi = len(aql_files) > 1
    for aql_file in aql_files:
        part = await fetch_data_from_qradar(
            client, offense_id, time_depth, aql_file,
            entity_value=entity_value, entity_type=entity_type,
        )
        if part is None:
            failed.append(aql_file)
            continue
        if multi:
            for ev in part:
                ev["Lens"] = aql_file
        events.extend(part)
    if failed and len(failed) == len(aql_files):
        return None, failed
    return events, failed


async def fetch_data_from_qradar(client: httpx.AsyncClient, offense_id: int, time_depth: str, aql_filename: str, entity_value: str = "", entity_type: str = ""):
    filepath = os.path.join(QUERIES_DIR, aql_filename)

    fallback_aql = (
        "SELECT DATEFORMAT(starttime, 'MM-dd HH:mm:ss') AS Time, "
        "QIDNAME(qid) AS EventName, username, sourceip, destinationip, destinationport, "
        "\"Logon Type\", \"Action\", \"Process Name\" "
        "FROM events WHERE INOFFENSE({offense_id}) ORDER BY starttime DESC LIMIT {limit} {time_depth}"
    )

    if not os.path.exists(filepath):
        logging.warning(f"AQL file '{aql_filename}' missing! Using hardcoded fallback.")
        aql_template = fallback_aql
    else:
        with open(filepath, "r", encoding="utf-8") as f:
            aql_template = f.read()

    global_limit = APP_CONFIG.get("aql_limit", 1500)
    source_ip = entity_value if entity_type in ("SourceIP", "DestinationIP") else ""
    username = entity_value if entity_type == "User" else ""
    aql = aql_template.format(
        offense_id=offense_id,
        time_depth=time_depth,
        limit=global_limit,
        source_ip=source_ip,
        username=username,
    )
    aql = _strip_aql_comments(aql)

    logging.debug(f"Executing Custom AQL ({aql_filename}): {aql}")
    
    try:
        search_url = f"{QRADAR_API_URL}/ariel/searches?query_expression={urllib.parse.quote(aql)}"
        response = await client.post(search_url, headers=HEADERS)
        
        if response.status_code not in (200, 201):
            logging.error(f"AQL Error: {response.text}")
            return None

        search_id = response.json().get("search_id")
        status = "WAIT"

        # Полінг з дедлайном. Без нього цикл не має виходу взагалі: INOFFENSE по широкому
        # вікну на гучному лог-сорсі легко дає 300+ с (міряно: 26 ГБ, 41% за 281 с), і такий
        # пошук тримає воркер gunicorn до кінця httpx-таймауту. Дедлайн → None → статус
        # AQL_ERROR → офенс лишається ВІДКРИТИМ, поллер переаналізує наступного циклу.
        deadline = time.monotonic() + float(APP_CONFIG.get("aql_poll_timeout_seconds", 180))

        while status != "COMPLETED":
            if time.monotonic() > deadline:
                logging.error(f"AQL timeout: пошук {search_id} не завершився за {APP_CONFIG.get('aql_poll_timeout_seconds', 180)} с — скасовую, офенс лишається відкритим.")
                await _delete_ariel_search(client, search_id)
                return None
            await asyncio.sleep(2)
            status_resp = await client.get(f"{QRADAR_API_URL}/ariel/searches/{search_id}", headers=HEADERS)
            status = status_resp.json().get("status", "ERROR")
            if status in ("ERROR", "CANCELED"):
                logging.error(f"AQL status={status} для пошуку {search_id}.")
                await _delete_ariel_search(client, search_id)
                return None

        results_resp = await client.get(f"{QRADAR_API_URL}/ariel/searches/{search_id}/results", headers=HEADERS)
        events = results_resp.json().get("events", [])
        await _delete_ariel_search(client, search_id)

        return [{k: v for k, v in e.items() if v and v != "null"} for e in events]

    except Exception as e:
        logging.error(f"Error fetching exact offense events: {e}")
        return None

async def remove_ip_from_refset(client: httpx.AsyncClient, refset_name: str, ip_value: str) -> tuple[bool, str]:
    """Видалити IP з QRadar reference set. Повертає (success, message).
    HTTP 200 — видалено, 404 — вже відсутнє (теж success), інше — помилка.
    Якщо config.botnet_dry_run=true, реальний DELETE не робиться, лише логування."""
    if APP_CONFIG.get("botnet_dry_run", False):
        logging.info(f"[DRY RUN] Would DELETE {ip_value} from reference set {refset_name}")
        return True, "dry_run"

    url = f"{QRADAR_API_URL}/reference_data/sets/{urllib.parse.quote(refset_name)}/{urllib.parse.quote(ip_value)}"
    try:
        resp = await client.delete(url, headers=HEADERS)
        if resp.status_code == 200:
            return True, "removed"
        if resp.status_code == 404:
            return True, "not_present"
        return False, f"http_{resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, f"exception: {e}"


async def close_qradar_offense(client: httpx.AsyncClient, offense_id: int, score: float):
    url = f"{QRADAR_API_URL}/siem/offenses/{offense_id}"
    params = {
        "status": "CLOSED",
        "closing_reason_id": 1 
    }
    
    try:
        response = await client.post(url, headers=HEADERS, params=params)
        if response.status_code == 200:
            logging.debug(f"OFFENSE {offense_id} CLOSED AUTOMATICALLY. Score ({score}) is below threshold.")
        elif response.status_code == 409:
            logging.debug(f"ℹ️ Offense {offense_id} is already closed in QRadar. Skipping auto-close.")
        else:
            logging.error(f"Failed to close offense {offense_id}: {response.text}")
    except Exception as e:
        logging.error(f"Error during closing offense: {e}")

async def fetch_refset_index(client: httpx.AsyncClient) -> dict:
    refset_names = APP_CONFIG.get("reference_sets", [])
    if not refset_names:
        return {}

    index: dict = {}
    for name in refset_names:
        url = f"{QRADAR_API_URL}/reference_data/sets/{urllib.parse.quote(name)}?fields=data"
        try:
            resp = await client.get(url, headers=HEADERS)
            if resp.status_code != 200:
                logging.warning(f"Reference set '{name}' fetch failed: HTTP {resp.status_code}")
                continue
            for item in resp.json().get("data", []):
                value = item.get("value")
                if value:
                    index.setdefault(value, []).append(name)
        except Exception as e:
            logging.warning(f"Reference set '{name}' fetch error: {e}")
    return index

async def get_refset_index(client: httpx.AsyncClient) -> dict:
    ttl = float(APP_CONFIG.get("refset_cache_ttl_seconds", 3600))
    now = time.time()
    if REFSET_CACHE["index"] is None or (now - REFSET_CACHE["ts"]) > ttl:
        logging.info("Reference set cache stale — refreshing from QRadar.")
        REFSET_CACHE["index"] = await fetch_refset_index(client)
        REFSET_CACHE["ts"] = now
        logging.info(f"Reference set cache loaded: {len(REFSET_CACHE['index'])} unique values across {len(APP_CONFIG.get('reference_sets', []))} sets.")
    return REFSET_CACHE["index"]

def build_asset_context_block(events: list, refset_index: dict) -> str:
    if not events or not refset_index:
        return ""

    seen_ips: set = set()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        for v in ev.values():
            if isinstance(v, str):
                seen_ips.update(IPV4_RE.findall(v))

    matched = {}
    for ip in seen_ips:
        tags = refset_index.get(ip)
        if tags:
            matched[ip] = tags
    if not matched:
        return ""

    lines = [f"{ip}: {', '.join(tags)}" for ip, tags in sorted(matched.items())]
    return (
        "--- INTERNAL ASSET CONTEXT ---\n"
        "(IPs below are tagged with their internal infrastructure role. Use this to refine the verdict: "
        "expected role behavior lowers the score, out-of-role behavior raises it.)\n"
        + "\n".join(lines)
        + "\n--- END ASSET CONTEXT ---\n\n"
    )

def _to_bool(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")

async def ask_ollama(client: httpx.AsyncClient, model: str, prompt: str, timeout: float = 600.0) -> tuple[float, str, str, bool]:
    num_ctx = MODELS_MAX_CTX.get(model, 32768)
    use_json_format = model in MODELS_WITH_JSON_FORMAT
    prompt_prefix = "" if use_json_format else "/no_think\n"

    payload = {
        "model": model,
        "prompt": f"{prompt_prefix}{prompt}",
        "stream": False,
        "options": {"num_ctx": num_ctx}
    }
    if use_json_format:
        payload["format"] = "json"

    response = await client.post(OLLAMA_API_URL, json=payload, timeout=timeout)
    response.raise_for_status()
    llm_text = response.json().get("response", "")

    if not llm_text.strip():
        raise ValueError("Empty response from Ollama")

    json_match = re.search(r'\{[^{}]*"score"[^{}]*\}', llm_text)
    parsed_json = json.loads(json_match.group()) if json_match else json.loads(llm_text.strip())

    return (
        float(parsed_json.get("score", 0.0)),
        parsed_json.get("verdict", "Unknown"),
        parsed_json.get("explanation", "No explanation provided."),
        _to_bool(parsed_json.get("mitigated", False))
    )

async def ask_openai(client: httpx.AsyncClient, model: str, prompt: str, timeout: float = 600.0) -> tuple[float, str, str, bool]:
    # llm01 (llama.cpp, OpenAI-сумісний /v1). response_format=json_object → строгий JSON.
    # Слово "json" уже присутнє у промпті (вимога OpenAI-формату), тож режим спрацьовує.
    base = APP_CONFIG.get("openai_base", "http://127.0.0.1:8080/v1").rstrip("/")
    endpoint = f"{base}/chat/completions"

    headers = {"Content-Type": "application/json"}
    api_key = APP_CONFIG.get("openai_api_key", "")
    if api_key:  # llm01 зараз без автентифікації; ключ додаємо лише якщо його увімкнуть на сервері
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "stream": False,
    }

    response = await client.post(endpoint, headers=headers, json=payload, timeout=timeout)
    response.raise_for_status()
    llm_text = response.json()["choices"][0]["message"]["content"]

    if not llm_text or not llm_text.strip():
        raise ValueError("Empty response from OpenAI-compatible endpoint")

    json_match = re.search(r'\{[^{}]*"score"[^{}]*\}', llm_text)
    parsed_json = json.loads(json_match.group()) if json_match else json.loads(llm_text.strip())

    return (
        float(parsed_json.get("score", 0.0)),
        parsed_json.get("verdict", "Unknown"),
        parsed_json.get("explanation", "No explanation provided."),
        _to_bool(parsed_json.get("mitigated", False))
    )

async def ask_vertex(client: httpx.AsyncClient, model: str, prompt: str) -> tuple[float, str, str, bool]:
    project_id = APP_CONFIG.get("vertex_project", "your-gcp-project-id")
    location = APP_CONFIG.get("vertex_location", "global")
    
    try:
        credentials = service_account.Credentials.from_service_account_file(
            VERTEX_KEY_PATH,
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        auth_req = google.auth.transport.requests.Request()
        credentials.refresh(auth_req)
        token = credentials.token
    except Exception as e:
        logging.error(f"Помилка авторизації Vertex AI: {e}")
        raise ValueError("Vertex AI Auth failed")

    if location == "global":
        host = "aiplatform.googleapis.com"
    else:
        host = f"{location}-aiplatform.googleapis.com"
        
    endpoint = f"https://{host}/v1/projects/{project_id}/locations/{location}/publishers/google/models/{model}:generateContent"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
            "maxOutputTokens": 4096,
            "topP": 0.9,
            "presencePenalty": 0.0
        }
    }

    raw_response_text = "No response"
    try:
        response = await client.post(endpoint, headers=headers, json=payload, timeout=600.0)
        raw_response_text = response.text
        response.raise_for_status()
        
        data = response.json()
        llm_text = data["candidates"][0]["content"]["parts"][0]["text"]
        parsed_json = json.loads(llm_text)
        
        if isinstance(parsed_json, list):
            parsed_json = parsed_json[0] if len(parsed_json) > 0 else {}
            
        return (
            float(parsed_json.get("score", 0.0)),
            parsed_json.get("verdict", "Unknown"),
            parsed_json.get("explanation", "No explanation provided."),
            _to_bool(parsed_json.get("mitigated", False))
        )

    except Exception as e:
        logging.error(f"Помилка парсингу відповіді Vertex AI: {e}")
        raise ValueError("Failed to parse Vertex AI response")
        
PROCESSING_STALE_MINUTES = 60  # PROCESSING старший за стільки хвилин — вважається крашнутим, можна перезапускати

@app.post("/universal-analysis")
async def universal_analysis(payload: UniversalTrigger):

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT status, (julianday('now') - julianday(last_updated)) * 24 * 60 AS age_min "
            "FROM offenses WHERE offense_id = ?",
            (payload.offense_id,),
        )
        row = cursor.fetchone()

        if row and not payload.is_manual:
            status, age_min = row[0], row[1] or 0
            if status == 'PROCESSED':
                logging.debug(f"⏭️ Офенс {payload.offense_id} вже оброблено раніше. Пропуск.")
                return {"status": "skipped", "message": "Already processed in DB"}
            if status == 'PROCESSING' and age_min < PROCESSING_STALE_MINUTES:
                logging.info(f"⏳ Офенс {payload.offense_id} зараз обробляється іншим процесом ({int(age_min)} хв тому). Пропуск.")
                return {"status": "skipped", "message": "Currently processing"}
            if status == 'PROCESSING':
                logging.warning(f"♻️ Офенс {payload.offense_id} застряг у PROCESSING на {int(age_min)} хв. Перезапуск.")

        cursor.execute("INSERT OR REPLACE INTO offenses (offense_id, status, last_updated) VALUES (?, ?, CURRENT_TIMESTAMP)",
                       (payload.offense_id, 'PROCESSING'))
        conn.commit()

    provider = APP_CONFIG.get("ai_provider", "ollama")
    fallback_provider = APP_CONFIG.get("ai_fallback", "")

    # Ручний глибокий аналіз може йти окремим провайдером: локальний llm01 не тягне
    # справжню deep-модель (32B ≈ 1 t/s на CPU), тож manual маршрутизуємо у хмару
    # (ai_manual_provider=vertex), а авто-тріаж лишаємо на швидкому локальному llm01.
    # Без ключа — стара поведінка (той самий провайдер для manual і auto).
    manual_provider = APP_CONFIG.get("ai_manual_provider")
    if payload.is_manual and manual_provider:
        provider = manual_provider

    def model_for(p: str) -> str:
        if p == "vertex":
            return APP_CONFIG.get("vertex_deep", "gemini-1.5-pro") if payload.is_manual else APP_CONFIG.get("vertex_fast", "gemini-1.5-flash")
        return APP_CONFIG.get("deep_model", "qwen3.5:27b") if payload.is_manual else APP_CONFIG.get("fast_model", "qwen2.5-coder:7b")

    active_model = model_for(provider)
    fallback_active = bool(fallback_provider) and fallback_provider != provider

    logging.debug(f"Запуск: Offense {payload.offense_id} | Режим: {'Ручний' if payload.is_manual else 'Авто'} | Провайдер: {provider} | Модель: {active_model} | Fallback: {fallback_provider or '—'}")

    timeout_seconds = APP_CONFIG.get("timeout_seconds", 600.0)
    # qradar_client: verify=False — QRadar використовує self-signed серти.
    # ai_client: verify=True — Vertex AI / Google ходить по валідних сертах, MitM захист обовʼязковий.
    async with httpx.AsyncClient(verify=False, timeout=timeout_seconds) as client, \
               httpx.AsyncClient(verify=True, timeout=timeout_seconds) as ai_client:

        details = await get_offense_details(client, payload.offense_id)
        if not details:
            raise HTTPException(status_code=404, detail="Offense not found or API error")

        # Вікно AQL відраховуємо від часу офенсу, а не від "now": інакше manual-аналіз
        # старого офенсу (або auto з затримкою) втрапляє у порожній період.
        # manual раніше жорстко брав 7 днів «передісторії». На гучних лог-сорсах це
        # перетворювало INOFFENSE у скан десятків ГБ (CNS141: 26 ГБ, 41% за 281 с), тобто
        # deep-режим не працював саме там, де найпотрібніший. Тепер обидва вікна — з конфігу:
        # manual_window_hours / auto_window_hours. Хочеш назад 7 днів — постав 168 у config.json.
        manual_hours = float(APP_CONFIG.get("manual_window_hours", 24))
        auto_hours = float(APP_CONFIG.get("auto_window_hours", 4))
        window_ms = int((manual_hours if payload.is_manual else auto_hours) * 60 * 60 * 1000)
        offense_start = details.get("start_time")
        offense_end = details.get("last_updated_time") or offense_start

        # Стеля на РОЗМАХ вікна, незалежно від віку офенсу. QRadar доливає події в той самий
        # офенс місяцями (реальний випадок: 955703 — відкритий 17.04.2026, 68 млн подій,
        # оновлювався щодня), і тоді START рахувався б від дати створення. INOFFENSE через
        # півроку історії Ariel не витягує: спрацьовує aql_poll_timeout_seconds, офенс іде в
        # AQL_ERROR, лишається відкритим і повторюється КОЖЕН цикл поллера — три таких офенси
        # зациклюють пайплайн.
        # Дефолт 192 год = 168 (escalate_window_hours) + доба запасу на тривалість офенсу.
        # Точно про те, коли стеля спрацьовує: коли (тривалість офенсу + вікно) > 192 год.
        # Для auto (4 год) це офенси, старші за ~8 діб; при ескалації (168 год) — старші за
        # ~добу, і тоді вона зрізає найдавнішу частину передісторії. Це свідомо: для
        # багатоденного офенсу найсвіжіші 8 діб і є правильними даними для тріажу.
        max_span_ms = int(float(APP_CONFIG.get("max_aql_span_hours", 192)) * 60 * 60 * 1000)

        def compute_time_depth(win_ms: int) -> str:
            if offense_start:
                stop_ms = int(offense_end) + 5 * 60 * 1000  # +5 хв буфер на пізні події
                start_ms = int(offense_start) - win_ms
                # Тримаємось свіжого кінця: обрізаємо початок, а не хвіст — найновіші події
                # для тріажу цінніші за передісторію піврічної давнини.
                floor_ms = stop_ms - max_span_ms
                if start_ms < floor_ms:
                    logging.warning(
                        f"⚠️ Офенс {payload.offense_id}: вікно AQL обрізане з "
                        f"{(stop_ms - start_ms) // 3600000} год до {max_span_ms // 3600000} год "
                        f"(офенс живе з {time.strftime('%Y-%m-%d', time.localtime(int(offense_start) / 1000))})."
                    )
                    start_ms = floor_ms
                return f"START {start_ms} STOP {stop_ms}"
            return f"LAST {max(1, min(win_ms, max_span_ms) // (60 * 60 * 1000))} HOURS"

        time_depth = compute_time_depth(window_ms)

        # Назви правил-учасників — фолбек-матчинг, коли опис офенсу = ім'я події, а не UC
        rules_map = await get_rules_map(client)
        contributing_rule_names = [rules_map.get(r.get("id"), "") for r in details.get("rules", [])]
        instruction, assignee, aql_filename, refset_cleanup, close_on_empty = get_dynamic_prompt(details['offense_name'], contributing_rule_names)

        # Композитний офенс: збираємо події з AQL УСІХ зматчених лінз, а не лише першої.
        # Промпт/assignee/refset лишаються від лінзи з найвищим пріоритетом (get_dynamic_prompt).
        lenses = get_matched_lenses(details['offense_name'], PROMPTS_FILE, contributing_rule_names)
        aql_files, seen_aql = [], set()
        for lens in lenses:
            if lens["aql_file"] not in seen_aql:
                seen_aql.add(lens["aql_file"])
                aql_files.append(lens["aql_file"])
        if not aql_files:
            aql_files = [aql_filename]      # шлях Default — лінз не зматчилось
        max_lenses = int(APP_CONFIG.get("max_aql_lenses_per_offense", 3))
        truncated = len(aql_files) > max_lenses
        if truncated:
            logging.info(f"Офенс {payload.offense_id}: лінз {len(aql_files)}, беру перші {max_lenses} за пріоритетом.")
            aql_files = aql_files[:max_lenses]

        # close_on_empty на композиті лишається лише якщо його мають УСІ лінзи: лінза без
        # прапорця означає, що для неї порожній результат — не «чисто», а «невідомо».
        # Одна лінза (≈92% трафіку) — поведінка не змінюється взагалі.
        #
        # Рахуємо за кількістю ЗМАТЧЕНИХ лінз (len(lenses)), а НЕ за кількістю тих, що реально
        # виконуємо (len(aql_files)): інакше max_aql_lenses_per_offense=1 обрізає список до
        # одного, умова не спрацьовує, перерахунок не виконується — і close_on_empty лишається
        # від лінзи №1. Композит тоді знову тихо закривається 0.0 з недослідженими шарами,
        # тобто рівно той баг (офенс 1234628/mng180), який мульти-лінза й лікує. Безпека не
        # має залежати від значення тюнінгового ключа.
        if len(lenses) > 1:
            close_on_empty = all(l["close_on_empty"] for l in lenses) and not truncated

        raw_events, failed_lenses = await fetch_events_multi_lens(
            client, payload.offense_id, time_depth, aql_files,
            entity_value=str(details.get("entity_value", "")),
            entity_type=details.get("entity_type", ""),
        )
        if failed_lenses and raw_events is not None:
            close_on_empty = False           # частина шарів невідома → порожньо ≠ «чисто»
            logging.warning(f"⚠️ Офенс {payload.offense_id}: AQL не виконався для {failed_lenses} — close_on_empty знято.")

        if raw_events is None:
            # AQL не виконався (422 ParseError / ERROR-статус / виняток). Порожній результат
            # != помилка: НЕ закриваємо офенс, навіть з close_on_empty. Інакше зламаний запит
            # тихо закриває реальні офенси як benign. Статус AQL_ERROR (≠ PROCESSED) → поллер
            # переаналізує наступного циклу, щойно AQL виправлено.
            logging.warning(f"⚠️ Офенс {payload.offense_id}: AQL не виконався (див. 'AQL Error' вище) — офенс залишаємо відкритим.")
            note_text = "AI Analysis (SKIPPED) | AQL execution failed (see middleware log: 422 ParseError or ERROR status). Offense left OPEN for manual review — NOT auto-closed."
            note_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}/notes?note_text={urllib.parse.quote(note_text)}"
            await client.post(note_url, headers=HEADERS)
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("UPDATE offenses SET status = 'AQL_ERROR', last_updated = CURRENT_TIMESTAMP WHERE offense_id = ?", (payload.offense_id,))
            return {"status": "error", "message": "AQL execution failed; offense left open"}

        if not raw_events:
            # close_on_empty: для monitoring-юзкейсів AQL сам відфільтровує benign, тож порожній
            # результат у auto-режимі = чисто => закриваємо як benign (score 0.0). Manual не чіпаємо
            # (аналітик сам тригернув — хай бачить). Без прапорця — стара поведінка (SKIP).
            if close_on_empty and not payload.is_manual:
                logging.info(f"✅ Офенс {payload.offense_id}: AQL без подій після benign-фільтра → авто-закриття (close_on_empty).")
                note_text = "AI Analysis (AUTO-CLOSE) | No risky events after AQL benign-filter — benign traffic only. Score: 0.0. Closed automatically."
                note_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}/notes?note_text={urllib.parse.quote(note_text)}"
                await client.post(note_url, headers=HEADERS)
                await close_qradar_offense(client, payload.offense_id, 0.0)
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("UPDATE offenses SET status = 'PROCESSED', last_updated = CURRENT_TIMESTAMP WHERE offense_id = ?", (payload.offense_id,))
                return {"status": "closed", "message": "No risky events after benign-filter; auto-closed", "score": 0.0}

            logging.warning(f"⚠️ Для офенсу {payload.offense_id} не знайдено подій.")
            note_text = "AI Analysis (SKIPPED) | No events found by AQL. Events might be filtered out, aged out, or based on flows."
            note_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}/notes?note_text={urllib.parse.quote(note_text)}"
            await client.post(note_url, headers=HEADERS)

            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("UPDATE offenses SET status = 'NO_EVENTS', last_updated = CURRENT_TIMESTAMP WHERE offense_id = ?", (payload.offense_id,))

            return {"status": "skipped", "message": "No events found"}

        refset_index = await get_refset_index(client)
        asset_block = build_asset_context_block(raw_events, refset_index)

        # Промпт збирається під конкретного провайдера: бюджет символів залежить від його
        # контексту (llm01 ctx 8192 vs Vertex 2 млн), тож при ескалації на tier-2 промпт
        # треба перезібрати, а не переслати нарізаний під llm01.
        def build_prompt(p: str, model: str, events, assets: str) -> str:
            # Хедер із двох правил читання доказів має дві версії: повна для провайдерів із
            # великим контекстом і стисла для llm01 (ctx 8192) — там кожні 700 символів
            # відбираються в логів, а на трьох найдовших юзкейсах бюджет і так нульовий.
            EVIDENCE_HEADER_FULL = (
                "HOW TO READ THE EVIDENCE (applies to every use case):\n"
                "1. A column that carries a QRadar log-source name — `Host`, `Hostname`, `LogSource`, `Src_Host` — "
                "has the form `<DSM name> @ <machine>`: `WindowsAuthServer @ mng170.modern.org`, "
                "`LinuxServer @ nginx2`, `Bind @ 172.17.61.157`. The prefix names the PARSER that read the log, "
                "NOT the machine's role — `WindowsAuthServer` is the DSM on every Windows box in the estate, "
                "ordinary workstations included. Never conclude that a machine is a domain controller, an "
                "authentication server, a DNS server or 'critical infrastructure' from that prefix, and never "
                "raise the score because of it; establish the role from the events themselves.\n"
                "2. An empty field means 'not mapped by the parser', never 'unknown' and never 'suspicious'. "
                "Sysmon does not populate Process Path on registry events, and QRadar leaves username, path or "
                "port blank for many event types. A blank path is NOT a user-writable path and NOT an unknown "
                "path — never raise the score because a column is empty.\n\n"
            )
            EVIDENCE_HEADER_SHORT = (
                "HOW TO READ THE EVIDENCE: a `Host`/`Hostname`/`LogSource` value is a QRadar log-source name "
                "(`<DSM> @ <machine>`, e.g. `WindowsAuthServer @ mng170` on an ordinary workstation) — the prefix "
                "names the parser, NOT the machine's role, so never call a host a DC, an auth server or critical "
                "infrastructure because of it. An empty column means 'not mapped by the parser', never 'unknown' "
                "and never 'user-writable' — never raise the score for a blank field.\n\n"
            )

            def render(logs_text: str, header: str) -> str:
                return (
                    "You are an expert Tier-2 SOC analyst. "
                    f"Context: QRadar triggered an offense named '{details['offense_name']}'. "
                    "However, SIEM rules often generate False Positives due to normal administrative tasks, "
                    "misconfigurations, or routine network traffic. Your primary job is to act as a filter.\n\n"
                    f"{header}"
                    f"Task: {instruction}\n\n"
                    f"{assets}"
                    f"--- START OF LOGS ---\n{logs_text}\n--- END OF LOGS ---\n\n"
                    "Based ONLY on the logs above, return a valid JSON object with keys "
                    "'score', 'verdict', 'explanation', and optionally 'mitigated'.\n\n"
                    "CRITICAL RULES FOR JSON:\n"
                    "1. 'score' must be a float between 0.0 and 1.0 based on the rubric below.\n"
                    "2. 'verdict' must be a short category string.\n"
                    "3. 'explanation' MUST BE EXTREMELY CONCISE. Strictly 1 short sentence, maximum 15 words. Do not write long paragraphs.\n"
                    "4. 'mitigated' (boolean, default false): set TRUE for a real/suspicious action that was FULLY BLOCKED, "
                    "DENIED, DROPPED or FAILED with NO successful outcome and no sign of an already-compromised internal asset "
                    "(e.g. an external IP whose scan or brute-force the firewall denied, or repeated auth failures with ZERO "
                    "successes). A true value CLOSES the offense while KEEPING any existing block in place (it does NOT unblock "
                    "the source). This is the correct, expected outcome for the high-volume 'real but already-stopped' case — "
                    "PREFER mitigated:true over a 0.7+ score whenever the threat was contained and no internal host needs action. "
                    "Leave it false ONLY when there is a successful/allowed connection, a real un-blocked consequence, or an "
                    "internal host that itself needs remediation.\n\n"
                    "CRITICAL SCORING RUBRIC for 'score' (float 0.0 to 1.0):\n"
                    "- 0.0 to 0.3: CLEAR FALSE POSITIVE. Routine administrative behavior, benign traffic, or no evidence of successful malicious action.\n"
                    "- 0.4 to 0.6: SUSPICIOUS BUT INCONCLUSIVE. Anomalous behavior without clear evidence of intent or impact.\n"
                    "- 0.7 to 0.8: HIGHLY SUSPICIOUS with a REAL, UN-BLOCKED consequence (a successful/allowed connection, lateral "
                    "movement, data egress). If the suspicious activity was blocked/denied/failed, it does NOT belong here — use "
                    "mitigated:true instead.\n"
                    "- 0.9 to 1.0: CONFIRMED COMPROMISE. Clear evidence of successful attack, data exfiltration, or unauthorized access.\n\n"
                    "ANTI-DEFAULT RULE: a score of 0.7+ pages a human analyst. Do NOT pick 0.7-0.8 because you are uncertain — "
                    "uncertainty WITHOUT a concrete un-blocked consequence is the 0.4-0.6 band (auto-closes) or, if the threat was "
                    "contained, mitigated:true. Use the EXACT verdict string defined in the TASK above; never emit a generic band "
                    "name such as 'Highly Suspicious' as the verdict.\n\n"
                    "If INTERNAL ASSET CONTEXT is provided above, weigh it: traffic matching an asset's expected role "
                    "(e.g., LDAP traffic to a 'LDAP Servers' IP) lowers the score; out-of-role behavior "
                    "(e.g., a 'Database Servers' IP making outbound web traffic) raises it.\n\n"
                    "Do NOT default to a high score just because an offense was triggered. Be highly skeptical. "
                    "Output ONLY the JSON object."
                )

            if p == "openai":
                # llm01 (llama.cpp) має лише ctx 8192, а лог/IP-текст токенізується щільно (~2.1 симв/токен).
                # Різати треба ВЕСЬ промпт, не лише логи: окрім виводу резервуємо фіксовану частину
                # (інструкція + рубрика/boilerplate + asset-блок), інакше llama.cpp віддає
                # 400 exceed_context_size_error. Бюджет під логи = залишок контексту.
                ctx = MODELS_MAX_CTX.get(model, 8192)
                CHARS_PER_TOK = 2.0        # консервативно (реально ~2.1 на логах) — краще недобрати, ніж 400
                OUTPUT_RESERVE_TOK = 1024  # короткий JSON-вердикт; із запасом
                # Розмір усього промпту без логів міряємо точно — порожнім рендером,
                # а не магічною константою: хедер і рубрика правляться, константа дрейфує
                # і тихо з'їдає бюджет логів (або віддає llama.cpp 400 exceed_context_size_error).
                header = EVIDENCE_HEADER_SHORT
                overhead = len(render("", header))
                max_chars = max(500, int((ctx - OUTPUT_RESERVE_TOK) * CHARS_PER_TOK) - overhead)
            elif p == "ollama":
                header = EVIDENCE_HEADER_FULL
                max_chars = int((MODELS_MAX_CTX.get(model, 32768) - 4096) * 3.5)
            else:
                header = EVIDENCE_HEADER_FULL
                max_chars = 2000000
            return render(str(events)[:max_chars], header)


        prompt = build_prompt(provider, active_model, raw_events, asset_block)

        async def call_provider(p: str, model: str, prompt_text: str):
            if p == "vertex":
                return await ask_vertex(ai_client, model, prompt_text)
            if p == "openai":
                # Сервер з llama.cpp (адреса — в openai_base; на 2026-08-08 це 10.2.10.1:8080
                # через node-local OVS-міст vmbr11, а НЕ стара 172.17.61.218 у VLAN 601).
                # Plain HTTP, TLS не задіяний → verify=False client.
                # Окремий таймаут, щоб повільна генерація на llm01 не блокувала fallback на Vertex.
                openai_timeout = float(APP_CONFIG.get("openai_timeout_seconds", APP_CONFIG.get("timeout_seconds", 600)))
                return await ask_openai(client, model, prompt_text, timeout=openai_timeout)
            # Ollama локальний (127.0.0.1, HTTP) — TLS не задіяний, можна будь-яким клієнтом.
            # Окремий короткий таймаут потрібен, щоб черга в Олламі не блокувала fallback на 10 хв.
            ollama_timeout = float(APP_CONFIG.get("ollama_timeout_seconds", APP_CONFIG.get("timeout_seconds", 600)))
            return await ask_ollama(client, model, prompt_text, timeout=ollama_timeout)

        used_provider = provider
        used_fallback = False
        try:
            score, verdict, explanation, mitigated = await call_provider(provider, active_model, prompt)
        except Exception as primary_err:
            if fallback_active:
                fb_model = model_for(fallback_provider)
                logging.warning(f"⚠️ Provider {provider} ({active_model}) failed for offense {payload.offense_id}: {primary_err}. Fallback → {fallback_provider} ({fb_model}).")
                try:
                    fb_prompt = build_prompt(fallback_provider, fb_model, raw_events, asset_block)
                    score, verdict, explanation, mitigated = await call_provider(fallback_provider, fb_model, fb_prompt)
                    used_provider = fallback_provider
                    used_fallback = True
                except Exception as fb_err:
                    logging.error(f"AI fallback ({fallback_provider}) also failed: {fb_err}")
                    with sqlite3.connect(DB_PATH) as conn:
                        conn.execute("UPDATE offenses SET status = 'AI_ERROR', last_updated = CURRENT_TIMESTAMP WHERE offense_id = ?", (payload.offense_id,))
                    return {"status": "error", "message": f"AI failed: primary={provider}:{primary_err}; fallback={fallback_provider}:{fb_err}"}
            else:
                logging.error(f"AI Provider ({provider}) error: {primary_err}")
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("UPDATE offenses SET status = 'AI_ERROR', last_updated = CURRENT_TIMESTAMP WHERE offense_id = ?", (payload.offense_id,))
                return {"status": "error", "message": f"AI analysis failed: {str(primary_err)}"}

        provider_label = f"{used_provider.upper()} [fallback]" if used_fallback else used_provider.upper()

        # Запобіжник на tier-1 навмисно ДО каскаду: інакше "компрометація + mitigated:true"
        # від дешевої моделі не пройшла б умову ескалації (`not mitigated`) і закрилась би,
        # так і не побачивши важку модель.
        guard_note = ""
        score, mitigated, g = enforce_compromise_guard(verdict, score, mitigated)
        if g:
            guard_note = g
            logging.warning(f"🚨 Офенс {payload.offense_id}: tier-1{g}")

        # --- КАСКАДНА ТРІАЖ (tier-2) ---
        # Локальна модель на tier-1 дешева, але заслабка, щоб самій вирішувати «будити аналітика».
        # Тому все, що вона підняла вище порога і НЕ визнала mitigated, переганяємо на важку
        # модель (Vertex) з ширшим вікном подій: ескалюється лише хвіст >0.6, тож вартість хмари
        # пропорційна реальному сигналу. Вердикт tier-2 повністю заміщає tier-1 — далі по коду
        # він і вирішує cleanup/закриття/призначення.
        escalated = False
        escalation_note = ""
        esc_provider = APP_CONFIG.get("escalate_provider", "vertex")
        if (
            APP_CONFIG.get("escalate_enabled", False)
            and not payload.is_manual
            and not mitigated
            and score > float(APP_CONFIG.get("escalate_threshold", 0.6))
            and esc_provider != used_provider  # tier-1 уже відпрацював на цьому провайдері (напр. пішов туди fallback-ом)
        ):
            esc_model = APP_CONFIG.get("escalate_model") or APP_CONFIG.get("vertex_deep", "gemini-1.5-pro")
            t1_score, t1_verdict = score, verdict
            try:
                esc_window_ms = int(float(APP_CONFIG.get("escalate_window_hours", 168)) * 60 * 60 * 1000)
                esc_time_depth = compute_time_depth(esc_window_ms)
                logging.info(f"⬆️ Офенс {payload.offense_id}: tier-1 {used_provider} дав score {t1_score} → ескалація на {esc_provider} ({esc_model}), вікно {esc_time_depth}")

                # Ті самі лінзи, що й на tier-1: вердикт tier-2 повністю заміщає tier-1,
                # тож дати важкій моделі вужчу вибірку — значить втратити шари доказів.
                esc_events, _esc_failed = await fetch_events_multi_lens(
                    client, payload.offense_id, esc_time_depth, aql_files,
                    entity_value=str(details.get("entity_value", "")),
                    entity_type=details.get("entity_type", ""),
                )
                # Ширша вибірка не вийшла (AQL впав або нічого не дав) — не привід гасити
                # ескалацію: важка модель варта запуску і на подіях tier-1.
                if not esc_events:
                    logging.warning(f"⚠️ Офенс {payload.offense_id}: ширша вибірка порожня/зламана — ескалюємо на подіях tier-1.")
                    esc_events = raw_events
                    esc_assets = asset_block
                else:
                    esc_assets = build_asset_context_block(esc_events, refset_index)

                esc_prompt = build_prompt(esc_provider, esc_model, esc_events, esc_assets)
                score, verdict, explanation, mitigated = await call_provider(esc_provider, esc_model, esc_prompt)
                # Вердикт tier-2 повністю заміщає tier-1, тож запобіжник треба прогнати ще раз.
                score, mitigated, g = enforce_compromise_guard(verdict, score, mitigated)
                if g:
                    guard_note = g
                    logging.warning(f"🚨 Офенс {payload.offense_id}: tier-2{g}")
                escalated = True
                provider_label = f"{used_provider.upper()}→{esc_provider.upper()} escalated"
                escalation_note = f" | Tier-1 ({used_provider}): {t1_score} {t1_verdict}"
                logging.info(f"✅ Офенс {payload.offense_id}: tier-2 {esc_provider} → score {score} ({verdict}), подій {len(esc_events)} за {esc_time_depth}")
            except Exception as esc_err:
                # Провал ескалації не має ламати конвеєр: лишаємо вердикт tier-1 як є.
                logging.error(f"⚠️ Ескалація офенсу {payload.offense_id} на {esc_provider} впала: {esc_err}. Лишаємо вердикт tier-1.")
                score, verdict = t1_score, t1_verdict
                escalation_note = f" | Tier-2 escalation FAILED ({esc_provider}) — tier-1 verdict kept"

        # Refset cleanup: для правил-наповнювачів радар уже додав sourceip у block-list.
        # Якщо AI визнав FP — знімаємо IP з refset, ефективно скасовуючи блок (PA-тег
        # сам стече по таймауту). Працює лише якщо в prompts.json вказано refset_cleanup
        # і entity офенсу — IP-адреса (SourceIP/DestinationIP).
        refset_action_note = ""
        if (
            refset_cleanup
            and score <= 0.6
            and not mitigated
            and details.get("entity_type") in ("SourceIP", "DestinationIP")
            and IPV4_RE.fullmatch(str(details.get("entity_value", "")).strip())
        ):
            ip_to_clean = str(details["entity_value"]).strip()
            ok, msg = await remove_ip_from_refset(client, refset_cleanup, ip_to_clean)
            if ok:
                logging.info(f"🧹 FP cleanup: removed {ip_to_clean} from {refset_cleanup} ({msg}) for offense {payload.offense_id}")
                refset_action_note = f" | Action: removed {ip_to_clean} from {refset_cleanup} ({msg})"
            else:
                logging.error(f"⚠️ FP cleanup failed for {ip_to_clean} from {refset_cleanup}: {msg}")
                refset_action_note = f" | Action: refset cleanup FAILED ({msg})"

        mitigated_note = " | Mitigated: blocked, no consequence — closed, block retained" if (mitigated and not payload.is_manual) else ""
        note_text = f"AI Analysis ({provider_label}) | Verdict: {verdict} | Score: {score} | Reason: {explanation}{refset_action_note}{mitigated_note}{guard_note}{escalation_note}"
        note_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}/notes?note_text={urllib.parse.quote(note_text)}"
        note_resp = await client.post(note_url, headers=HEADERS)

        if note_resp.status_code in (200, 201):
            logging.debug(f"Offense {payload.offense_id} successfully updated with note.")

        if mitigated and not payload.is_manual:
            # Реальна/підозріла активність, але повністю заблокована, без наслідків → закриваємо офенс,
            # АЛЕ блок лишаємо (refset cleanup пропущено вище). Аналітика не турбуємо.
            logging.info(f"🛡️ Офенс {payload.offense_id} mitigated (заблоковано, без наслідків). Закриття, блок збережено.")
            await close_qradar_offense(client, payload.offense_id, score)
        elif score <= 0.6 and not payload.is_manual:
            # Низький скор + авто-режим → автозакриття. Не призначаємо нікого, бо офенс закриється.
            # У ручному режимі офенс не закриваємо — аналітик сам натиснув "аналізувати" і хоче побачити результат.
            logging.debug(f"Score {score} is low. Triggering auto-close for Offense {payload.offense_id}")
            await close_qradar_offense(client, payload.offense_id, score)
        elif assignee:
            # Високий скор → офенс лишається відкритим, передаємо аналітику з prompts.json
            assign_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}?assigned_to={assignee}"
            assign_resp = await client.post(assign_url, headers=HEADERS)
            if assign_resp.status_code in (200, 201):
                reason = "ручний режим" if payload.is_manual and score <= 0.6 else f"score {score} > 0.6"
                logging.info(f"👤 Офенс {payload.offense_id} призначено на {assignee} ({reason})")
            else:
                logging.error(f"⚠️ Не вдалося призначити офенс {payload.offense_id} на {assignee}: {assign_resp.text}")

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                UPDATE offenses
                SET status = 'PROCESSED', score = ?, verdict = ?, escalated = ?, last_updated = CURRENT_TIMESTAMP
                WHERE offense_id = ?
            """, (score, verdict, 1 if escalated else 0, payload.offense_id))

    logging.info(f"✅ Офенс {payload.offense_id} оброблено | Режим: {'Ручний' if payload.is_manual else 'Авто'} | Провайдер: {provider_label} | Вердикт: {verdict} | Score: {score} | Mitigated: {mitigated}")
    return {"status": "success", "offense_id": payload.offense_id, "verdict": verdict, "score": score, "explanation": explanation, "mitigated": mitigated, "provider": used_provider, "fallback": used_fallback, "escalated": escalated}


CHAT_PAGE_HTML = r"""<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>llm01 — пісочниця</title>
<style>
  :root {
    --bg:#f6f7f9; --panel:#ffffff; --ink:#1f2328; --muted:#6b7280; --line:#e5e7eb;
    --accent:#005A9E; --user:#e8f0fe; --bot:#f3f4f6; --warn:#b45309; --err:#b91c1c;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#16181d; --panel:#1e2128; --ink:#e6e8eb; --muted:#9aa1ab; --line:#2c3038;
            --accent:#4a9eff; --user:#25344a; --bot:#252932; --warn:#e0a33e; --err:#ff7b72; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 -apple-system,Segoe UI,Roboto,Arial,sans-serif; }
  header { display:flex; align-items:center; gap:12px; padding:12px 18px; border-bottom:1px solid var(--line); background:var(--panel); position:sticky; top:0; z-index:5; }
  header h1 { font-size:16px; margin:0; font-weight:650; }
  header .meta { color:var(--muted); font-size:12.5px; }
  header a { color:var(--accent); text-decoration:none; font-size:13px; margin-left:auto; }
  main { max-width:900px; margin:0 auto; padding:18px 18px 220px; }
  .msg { display:flex; margin:14px 0; }
  .msg .bubble { padding:10px 14px; border-radius:12px; white-space:pre-wrap; word-wrap:break-word; max-width:82%; }
  .msg.user { justify-content:flex-end; }
  .msg.user .bubble { background:var(--user); }
  .msg.bot .bubble { background:var(--bot); }
  .msg .who { font-size:11px; color:var(--muted); margin-bottom:4px; text-transform:uppercase; letter-spacing:.04em; }
  .note { color:var(--warn); font-size:13px; margin:10px 0; }
  .err { color:var(--err); font-size:13.5px; margin:10px 0; white-space:pre-wrap; }
  .composer { position:fixed; left:0; right:0; bottom:0; background:var(--panel); border-top:1px solid var(--line); padding:12px 18px 14px; }
  .composer .inner { max-width:900px; margin:0 auto; }
  textarea { width:100%; resize:vertical; min-height:76px; padding:11px 12px; border:1px solid var(--line);
             border-radius:10px; background:var(--bg); color:var(--ink); font:inherit; }
  .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:9px; }
  .row label { font-size:12.5px; color:var(--muted); display:flex; align-items:center; gap:6px; }
  select, input[type=number] { padding:6px 8px; border:1px solid var(--line); border-radius:8px;
             background:var(--bg); color:var(--ink); font:inherit; font-size:13px; }
  input[type=number] { width:82px; }
  button { padding:9px 18px; border:0; border-radius:9px; background:var(--accent); color:#fff; font-size:14px; cursor:pointer; }
  button.ghost { background:transparent; color:var(--muted); border:1px solid var(--line); }
  button:disabled { opacity:.5; cursor:default; }
  .spacer { flex:1 1 auto; }
  details { margin-top:9px; }
  summary { cursor:pointer; font-size:12.5px; color:var(--muted); }
  details textarea { min-height:60px; margin-top:8px; }
  .tokens { font-size:12px; color:var(--muted); }
  .cursor::after { content:"▍"; opacity:.6; }
</style>
</head>
<body>
<header>
  <h1>🧪 llm01 — пісочниця</h1>
  <span class="meta" id="meta">…</span>
  <a href="/">← аналіз офенсу</a>
</header>

<main id="log">
  <div class="note">Прямий діалог із on-prem моделлю. Нічого не зберігається: історія живе лише у цій вкладці, оновлення сторінки її стирає. Промпти радара (prompts/*.md) цей екран не читає і не змінює.</div>
</main>

<div class="composer"><div class="inner">
  <textarea id="input" placeholder="Промпт… (Enter — надіслати, Shift+Enter — новий рядок)"></textarea>
  <details>
    <summary>Системний промпт і параметри</summary>
    <textarea id="system" placeholder="System prompt (необовʼязково)"></textarea>
  </details>
  <div class="row">
    <label>модель <select id="model"></select></label>
    <label>temp <input type="number" id="temp" value="0.7" min="0" max="2" step="0.1"></label>
    <label>max tokens <input type="number" id="maxtok" value="512" min="16" max="4096" step="64"></label>
    <span class="tokens" id="tokens"></span>
    <span class="spacer"></span>
    <button class="ghost" id="clear" type="button">Очистити</button>
    <button id="send" type="button">Надіслати</button>
    <button class="ghost" id="stop" type="button" style="display:none">Стоп</button>
  </div>
</div></div>

<script>
const log = document.getElementById('log');
const input = document.getElementById('input');
const sysBox = document.getElementById('system');
const modelSel = document.getElementById('model');
const sendBtn = document.getElementById('send');
const stopBtn = document.getElementById('stop');
const clearBtn = document.getElementById('clear');
const tokensEl = document.getElementById('tokens');
let history = [];   // тільки в памʼяті вкладки
let ctrl = null;
let ctxLimit = 8192;

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function addMsg(role, text) {
  const wrap = document.createElement('div');
  wrap.className = 'msg ' + (role === 'user' ? 'user' : 'bot');
  wrap.innerHTML = '<div><div class="who">' + (role === 'user' ? 'ти' : 'llm01') +
                   '</div><div class="bubble"></div></div>';
  wrap.querySelector('.bubble').textContent = text;
  log.appendChild(wrap);
  window.scrollTo(0, document.body.scrollHeight);
  return wrap.querySelector('.bubble');
}
function addLine(cls, text) {
  const d = document.createElement('div');
  d.className = cls; d.textContent = text;
  log.appendChild(d); window.scrollTo(0, document.body.scrollHeight);
}
function updTokens() {
  const chars = history.reduce((n, m) => n + m.content.length, 0) + sysBox.value.length + input.value.length;
  const est = Math.round(chars / 2);
  tokensEl.textContent = '~' + est + ' / ' + ctxLimit + ' ток.' + (est > ctxLimit * 0.8 ? ' (скоро обріжеться)' : '');
}
input.addEventListener('input', updTokens);
sysBox.addEventListener('input', updTokens);

fetch('/chat/models').then(r => r.json()).then(j => {
  document.getElementById('meta').textContent = j.base + (j.error ? ' — ' + j.error : '');
  (j.models || []).forEach(m => {
    const o = document.createElement('option');
    o.value = m.id; o.textContent = m.id + (m.n_ctx ? ' (ctx ' + m.n_ctx + ')' : '');
    if (m.n_ctx) o.dataset.ctx = m.n_ctx;
    modelSel.appendChild(o);
  });
  if (!modelSel.options.length && j.default) {
    const o = document.createElement('option'); o.value = j.default; o.textContent = j.default;
    modelSel.appendChild(o);
  }
  ctxLimit = parseInt(modelSel.selectedOptions[0]?.dataset.ctx || '8192', 10);
  updTokens();
});
modelSel.addEventListener('change', () => {
  ctxLimit = parseInt(modelSel.selectedOptions[0]?.dataset.ctx || '8192', 10); updTokens();
});

clearBtn.onclick = () => {
  history = [];
  log.querySelectorAll('.msg, .err, .note.run').forEach(n => n.remove());
  updTokens();
};

input.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
});
sendBtn.onclick = send;
stopBtn.onclick = () => { if (ctrl) ctrl.abort(); };

async function send() {
  const text = input.value.trim();
  if (!text || ctrl) return;
  input.value = '';
  addMsg('user', text);
  history.push({role: 'user', content: text});
  updTokens();

  const bubble = addMsg('assistant', '');
  bubble.classList.add('cursor');
  sendBtn.disabled = true; stopBtn.style.display = '';
  ctrl = new AbortController();
  let acc = '';

  try {
    const resp = await fetch('/chat/send', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, signal: ctrl.signal,
      body: JSON.stringify({
        messages: history, model: modelSel.value, system: sysBox.value,
        temperature: parseFloat(document.getElementById('temp').value) || 0.7,
        max_tokens: parseInt(document.getElementById('maxtok').value, 10) || 512
      })
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      buf += dec.decode(value, {stream: true});
      const parts = buf.split('\n\n');
      buf = parts.pop();
      for (const part of parts) {
        const line = part.split('\n').find(l => l.startsWith('data:'));
        if (!line) continue;
        const ev = JSON.parse(line.slice(5).trim());
        if (ev.d) { acc += ev.d; bubble.textContent = acc; window.scrollTo(0, document.body.scrollHeight); }
        else if (ev.note) addLine('note run', ev.note);
        else if (ev.error) addLine('err', ev.error);
      }
    }
  } catch (e) {
    if (e.name !== 'AbortError') addLine('err', String(e));
  } finally {
    bubble.classList.remove('cursor');
    if (acc) history.push({role: 'assistant', content: acc});
    ctrl = null; sendBtn.disabled = false; stopBtn.style.display = 'none';
    updTokens(); input.focus();
  }
}
input.focus();
</script>
</body>
</html>"""


# --- ПІСОЧНИЦЯ llm01 (окремий чат-UI, /chat) ------------------------------------
# Прямий діалог із on-prem llm01 (llama.cpp, OpenAI /v1) без жодної триаж-обгортки:
# промпт користувача йде в модель як є. НІЧОГО не зберігається — ні на диску, ні в
# ai_state.db, ні в логах: історія живе лише у вкладці браузера. Радар-промпти
# (prompts/*.md) цей інтерфейс не читає і не пише.

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    model: str = ""
    system: str = ""
    temperature: float = 0.7
    max_tokens: int = 512


def _chat_endpoint() -> tuple[str, dict]:
    base = APP_CONFIG.get("openai_base", "http://127.0.0.1:8080/v1").rstrip("/")
    headers = {"Content-Type": "application/json"}
    api_key = APP_CONFIG.get("openai_api_key", "")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return base, headers


def _fit_history(messages: list[dict], model: str, max_tokens: int) -> tuple[list[dict], int]:
    """Ріже історію під контекст llm01 (8192 на слот), лишаючи найсвіжіше.

    Системне повідомлення тримаємо завжди. Оцінка та сама, що й у build_prompt:
    ~2 символи на токен — консервативно, краще недобрати, ніж отримати
    500 'Context size has been exceeded' від llama.cpp."""
    ctx = MODELS_MAX_CTX.get(model, 8192)
    budget_chars = max(500, int((ctx - max_tokens - 256) * 2.0))
    system = [m for m in messages if m["role"] == "system"]
    rest = [m for m in messages if m["role"] != "system"]
    used = sum(len(m["content"]) for m in system)
    kept: list[dict] = []
    for m in reversed(rest):
        if used + len(m["content"]) > budget_chars and kept:
            break
        used += len(m["content"])
        kept.append(m)
    kept.reverse()
    dropped = len(rest) - len(kept)
    return system + kept, dropped


@app.get("/chat/models")
async def chat_models():
    """Список моделей, які llm01 реально віддає (llama.cpp /v1/models)."""
    base, headers = _chat_endpoint()
    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            r = await client.get(f"{base}/models", headers=headers)
            r.raise_for_status()
            data = r.json().get("data") or []
            out = []
            for m in data:
                out.append({"id": m.get("id"), "n_ctx": (m.get("meta") or {}).get("n_ctx")})
            return {"models": out, "base": base,
                    "default": APP_CONFIG.get("fast_model", "")}
    except Exception as e:
        return {"models": [], "base": base, "error": str(e)[:200],
                "default": APP_CONFIG.get("fast_model", "")}


@app.post("/chat/send")
async def chat_send(req: ChatRequest):
    """Стрімить відповідь llm01 у браузер (SSE). Тіло запиту ніде не осідає."""
    base, headers = _chat_endpoint()
    model = req.model or APP_CONFIG.get("fast_model", "qwen2.5-coder-3b")
    max_tokens = max(16, min(int(req.max_tokens or 512), 4096))

    msgs = []
    if (req.system or "").strip():
        msgs.append({"role": "system", "content": req.system.strip()})
    for m in req.messages:
        if m.role in ("user", "assistant") and (m.content or "").strip():
            msgs.append({"role": m.role, "content": m.content})
    if not msgs:
        raise HTTPException(status_code=400, detail="Порожній запит")

    msgs, dropped = _fit_history(msgs, model, max_tokens)

    payload = {
        "model": model,
        "messages": msgs,
        "temperature": max(0.0, min(float(req.temperature), 2.0)),
        "max_tokens": max_tokens,
        "stream": True,
    }
    timeout = float(APP_CONFIG.get("openai_timeout_seconds", 300))

    async def event_stream():
        if dropped:
            yield "data: " + json.dumps({"note": f"Найстаріші {dropped} повідомлень обрізано під контекст моделі"}) + "\n\n"
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
                async with client.stream("POST", f"{base}/chat/completions",
                                         headers=headers, json=payload) as resp:
                    if resp.status_code >= 400:
                        body = (await resp.aread()).decode("utf-8", "replace")[:400]
                        # Один слот на llama.cpp: поки поллер тріажить офенс, чат
                        # отримує 500 'Context size has been exceeded'. Кажемо прямо.
                        hint = " — llm01 зараз зайнятий тріажем офенсів, спробуй ще раз" if resp.status_code >= 500 else ""
                        yield "data: " + json.dumps({"error": f"llm01 {resp.status_code}: {body}{hint}"}) + "\n\n"
                        return
                    async for line in resp.aiter_lines():
                        if not line or not line.startswith("data:"):
                            continue
                        chunk = line[5:].strip()
                        if chunk == "[DONE]":
                            break
                        try:
                            delta = json.loads(chunk)["choices"][0].get("delta", {}).get("content")
                        except Exception:
                            continue
                        if delta:
                            yield "data: " + json.dumps({"d": delta}) + "\n\n"
        except Exception as e:
            yield "data: " + json.dumps({"error": f"{type(e).__name__}: {str(e)[:200]}"}) + "\n\n"
        yield "data: " + json.dumps({"done": True}) + "\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@app.get("/chat", response_class=HTMLResponse)
async def chat_ui():
    return CHAT_PAGE_HTML


@app.get("/", response_class=HTMLResponse)
async def get_web_ui():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>QRadar AI Assistant</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f7f6; padding: 40px; }
            .container { max-width: 500px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
            h2 { color: #333; text-align: center; }
            label { font-weight: bold; margin-top: 10px; display: block; }
            input { width: 100%; padding: 10px; margin-top: 5px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background-color: #005A9E; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
            button:hover { background-color: #004578; }
            #result { margin-top: 20px; padding: 15px; border-radius: 4px; display: none; text-align: center; font-weight: bold; }
            .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .loading { background-color: #e2e3e5; color: #383d41; border: 1px solid #d6d8db; }
            .hint { font-size: 0.9em; color: #666; margin-bottom: 20px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🧠 QRadar AI Assistant</h2>
            <div class="hint">Просто введіть номер інциденту. Система сама знайде IP, тип події та логіку правила!</div>
            <form id="aiForm">
                <label>Offense ID:</label>
                <input type="number" id="offense_id" required placeholder="Наприклад: 934415">

                <button type="button" onclick="runAnalysis()" id="submitBtn">🚀 Запустити аналітику</button>
            </form>
            <div class="hint" style="margin-top:18px"><a href="/chat" style="color:#005A9E">🧪 Пісочниця llm01</a> — прямий діалог з моделлю, без тріаж-обгортки</div>
            
            <div id="result"></div>
        </div>

<script>
async function runAnalysis() {
    const input = document.getElementById('offense_id').value;
    const offenseId = input.replace(/\D/g, ''); 
    const resultDiv = document.getElementById('result');
    
    if (!offenseId) {
        alert('Будь ласка, введіть коректний ID інциденту!');
        return;
    }

    const payload = {
        offense_id: parseInt(offenseId),
        is_manual: true
    };

    resultDiv.style.display = 'block';
    resultDiv.className = 'loading';
    resultDiv.innerText = "⏳ Аналізую логи (це може зайняти хвилину)...";

    try {
        const response = await fetch('/universal-analysis', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            const data = await response.json();
            
            // ПЕРЕВІРЯЄМО СТАТУС ВІДПОВІДІ
            if (data.status === "success") {
                resultDiv.className = 'success';
                resultDiv.innerText = `✅ Аналіз завершено!\nВердикт: ${data.verdict}\nОцінка (Score): ${data.score}`;
            } else if (data.status === "skipped") {
                resultDiv.className = 'error'; // Можна зробити жовтий стиль для skipped, але поки буде як error
                resultDiv.innerText = `⚠️ Пропущено: ${data.message}`;
            } else {
                resultDiv.className = 'error';
                resultDiv.innerText = `❌ Помилка: ${data.message}`;
            }
            
        } else {
            resultDiv.className = 'error';
            resultDiv.innerText = "❌ Помилка сервера: " + response.status;
        }
    } catch (error) {
        console.error("Помилка мережі:", error);
        resultDiv.className = 'error';
        resultDiv.innerText = "❌ Помилка мережі. Перевірте консоль F12.";
    }
}
</script>
    </body>
    </html>
    """
    return html_content