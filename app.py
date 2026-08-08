from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
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

if not DEBUG_MODE:
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
# -----------------------------------------------

# Динамічні глобальні змінні
QRADAR_API_URL = f"{APP_CONFIG['qradar_url']}/api"
OLLAMA_API_URL = f"{APP_CONFIG['ollama_url']}/api/generate"
HEADERS = {
    "SEC": APP_CONFIG['qradar_token'],
    "Content-Type": "application/json",
    "Accept": "application/json"
}

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

        while status != "COMPLETED":
            await asyncio.sleep(2)
            status_resp = await client.get(f"{QRADAR_API_URL}/ariel/searches/{search_id}", headers=HEADERS)
            status = status_resp.json().get("status", "ERROR")
            if status == "ERROR": return None

        results_resp = await client.get(f"{QRADAR_API_URL}/ariel/searches/{search_id}/results", headers=HEADERS)
        events = results_resp.json().get("events", [])
        
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
    if payload.is_manual and APP_CONFIG.get("ai_manual_provider"):
        provider = APP_CONFIG["ai_manual_provider"]

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
        window_ms = (7 * 24 * 60 * 60 * 1000) if payload.is_manual else (4 * 60 * 60 * 1000)
        offense_start = details.get("start_time")
        offense_end = details.get("last_updated_time") or offense_start

        def compute_time_depth(win_ms: int) -> str:
            if offense_start:
                start_ms = int(offense_start) - win_ms
                stop_ms = int(offense_end) + 5 * 60 * 1000  # +5 хв буфер на пізні події
                return f"START {start_ms} STOP {stop_ms}"
            return f"LAST {max(1, win_ms // (60 * 60 * 1000))} HOURS"

        time_depth = compute_time_depth(window_ms)

        # Назви правил-учасників — фолбек-матчинг, коли опис офенсу = ім'я події, а не UC
        rules_map = await get_rules_map(client)
        contributing_rule_names = [rules_map.get(r.get("id"), "") for r in details.get("rules", [])]
        instruction, assignee, aql_filename, refset_cleanup, close_on_empty = get_dynamic_prompt(details['offense_name'], contributing_rule_names)

        raw_events = await fetch_data_from_qradar(
            client, payload.offense_id, time_depth, aql_filename,
            entity_value=str(details.get("entity_value", "")),
            entity_type=details.get("entity_type", ""),
        )
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
            if p == "openai":
                # llm01 (llama.cpp) має лише ctx 8192, а лог/IP-текст токенізується щільно (~2.1 симв/токен).
                # Різати треба ВЕСЬ промпт, не лише логи: окрім виводу резервуємо фіксовану частину
                # (інструкція + рубрика/boilerplate + asset-блок), інакше llama.cpp віддає
                # 400 exceed_context_size_error. Бюджет під логи = залишок контексту.
                ctx = MODELS_MAX_CTX.get(model, 8192)
                CHARS_PER_TOK = 2.0        # консервативно (реально ~2.1 на логах) — краще недобрати, ніж 400
                OUTPUT_RESERVE_TOK = 1024  # короткий JSON-вердикт; із запасом
                fixed_chars = len(instruction) + len(assets) + 3200  # 3200 ≈ константна рубрика/boilerplate промпту
                max_chars = max(500, int((ctx - OUTPUT_RESERVE_TOK) * CHARS_PER_TOK) - fixed_chars)
            elif p == "ollama":
                max_chars = int((MODELS_MAX_CTX.get(model, 32768) - 4096) * 3.5)
            else:
                max_chars = 2000000
            logs_text = str(events)[:max_chars]

            return (
                "You are an expert Tier-2 SOC analyst. "
                f"Context: QRadar triggered an offense named '{details['offense_name']}'. "
                "However, SIEM rules often generate False Positives due to normal administrative tasks, "
                "misconfigurations, or routine network traffic. Your primary job is to act as a filter.\n\n"
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

        prompt = build_prompt(provider, active_model, raw_events, asset_block)

        async def call_provider(p: str, model: str, prompt_text: str):
            if p == "vertex":
                return await ask_vertex(ai_client, model, prompt_text)
            if p == "openai":
                # llm01 (172.17.61.218:8080) — plain HTTP у VLAN 601, TLS не задіяний → verify=False client.
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

                esc_events = await fetch_data_from_qradar(
                    client, payload.offense_id, esc_time_depth, aql_filename,
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
        note_text = f"AI Analysis ({provider_label}) | Verdict: {verdict} | Score: {score} | Reason: {explanation}{refset_action_note}{mitigated_note}{escalation_note}"
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