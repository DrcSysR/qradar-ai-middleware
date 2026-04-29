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

from prompts_loader import get_dynamic_prompt as _get_dynamic_prompt

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
}
MODELS_WITH_JSON_FORMAT = {"qwen2.5-coder:7b", "qwen2.5-coder:14b", "qwen2.5-coder:32b"}

# --- ЗАВАНТАЖЕННЯ КОНФІГУРАЦІЇ ---
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Failed to load config.json: {e}")
    
    return {
        "qradar_url": "https://127.0.0.1",
        "qradar_token": "",
        "ollama_url": "http://127.0.0.1:11434",
        "fast_model": "qwen2.5-coder:7b",
        "deep_model": "qwen2.5-coder:32b",
        "timeout_seconds": 600,
        "aql_limit": 1500,
        "debug_mode": False
    }

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
init_db()

app = FastAPI(title="QRadar AI Middleware")

# Нова проста модель - приймаємо ТІЛЬКИ номер інциденту
class UniversalTrigger(BaseModel):
    offense_id: int
    is_manual: bool = False

def get_dynamic_prompt(rule_name):
    return _get_dynamic_prompt(rule_name, PROMPTS_FILE, PROMPTS_DIR)



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
    }

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

    logging.debug(f"Executing Custom AQL ({aql_filename}): {aql}")
    
    try:
        search_url = f"{QRADAR_API_URL}/ariel/searches?query_expression={urllib.parse.quote(aql)}"
        response = await client.post(search_url, headers=HEADERS)
        
        if response.status_code not in (200, 201):
            logging.error(f"AQL Error: {response.text}")
            return []
            
        search_id = response.json().get("search_id")
        status = "WAIT"
        
        while status != "COMPLETED":
            await asyncio.sleep(2)
            status_resp = await client.get(f"{QRADAR_API_URL}/ariel/searches/{search_id}", headers=HEADERS)
            status = status_resp.json().get("status", "ERROR")
            if status == "ERROR": return []

        results_resp = await client.get(f"{QRADAR_API_URL}/ariel/searches/{search_id}/results", headers=HEADERS)
        events = results_resp.json().get("events", [])
        
        return [{k: v for k, v in e.items() if v and v != "null"} for e in events]

    except Exception as e:
        logging.error(f"Error fetching exact offense events: {e}")
        return []

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

async def ask_ollama(client: httpx.AsyncClient, model: str, prompt: str, timeout: float = 600.0) -> tuple[float, str, str]:
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
        parsed_json.get("explanation", "No explanation provided.")
    )

async def ask_vertex(client: httpx.AsyncClient, model: str, prompt: str) -> tuple[float, str, str]:
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
            parsed_json.get("explanation", "No explanation provided.")
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
    time_depth = "LAST 7 DAYS" if payload.is_manual else "LAST 24 HOURS"

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
            
        instruction, assignee, aql_filename = get_dynamic_prompt(details['offense_name'])

        raw_events = await fetch_data_from_qradar(
            client, payload.offense_id, time_depth, aql_filename,
            entity_value=str(details.get("entity_value", "")),
            entity_type=details.get("entity_type", ""),
        )
        if not raw_events:
            logging.warning(f"⚠️ Для офенсу {payload.offense_id} не знайдено подій.")
            note_text = "AI Analysis (SKIPPED) | No events found by AQL. Events might be filtered out, aged out, or based on flows."
            note_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}/notes?note_text={urllib.parse.quote(note_text)}"
            await client.post(note_url, headers=HEADERS)

            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("UPDATE offenses SET status = 'NO_EVENTS', last_updated = CURRENT_TIMESTAMP WHERE offense_id = ?", (payload.offense_id,))
            
            return {"status": "skipped", "message": "No events found"}

        max_chars = int((MODELS_MAX_CTX.get(active_model, 32768) - 4096) * 3.5) if provider == "ollama" else 2000000
        logs_text = str(raw_events)[:max_chars]

        prompt = (
            "You are an expert Tier-2 SOC analyst. "
            f"Context: QRadar triggered an offense named '{details['offense_name']}'. "
            "However, SIEM rules often generate False Positives due to normal administrative tasks, "
            "misconfigurations, or routine network traffic. Your primary job is to act as a filter.\n\n"
            f"Task: {instruction}\n\n"
            f"--- START OF LOGS ---\n{logs_text}\n--- END OF LOGS ---\n\n"
            "Based ONLY on the logs above, return a valid JSON object with exactly THREE keys: "
            "'score', 'verdict', and 'explanation'.\n\n"
            "CRITICAL RULES FOR JSON:\n"
            "1. 'score' must be a float between 0.0 and 1.0 based on the rubric below.\n"
            "2. 'verdict' must be a short category string.\n"
            "3. 'explanation' MUST BE EXTREMELY CONCISE. Strictly 1 short sentence, maximum 15 words. Do not write long paragraphs.\n\n"
            "CRITICAL SCORING RUBRIC for 'score' (float 0.0 to 1.0):\n"
            "- 0.0 to 0.3: CLEAR FALSE POSITIVE. Routine administrative behavior, benign traffic, or no evidence of successful malicious action.\n"
            "- 0.4 to 0.6: SUSPICIOUS BUT INCONCLUSIVE. Anomalous behavior without clear evidence of intent or impact.\n"
            "- 0.7 to 0.8: HIGHLY SUSPICIOUS. Strong indicators of malicious activity (e.g., failed brute force, scanning).\n"
            "- 0.9 to 1.0: CONFIRMED COMPROMISE. Clear evidence of successful attack, data exfiltration, or unauthorized access.\n\n"
            "Do NOT default to a high score just because an offense was triggered. Be highly skeptical. "
            "Output ONLY the JSON object."
        )

        async def call_provider(p: str, model: str):
            if p == "vertex":
                return await ask_vertex(ai_client, model, prompt)
            # Ollama локальний (127.0.0.1, HTTP) — TLS не задіяний, можна будь-яким клієнтом.
            # Окремий короткий таймаут потрібен, щоб черга в Олламі не блокувала fallback на 10 хв.
            ollama_timeout = float(APP_CONFIG.get("ollama_timeout_seconds", APP_CONFIG.get("timeout_seconds", 600)))
            return await ask_ollama(client, model, prompt, timeout=ollama_timeout)

        used_provider = provider
        used_fallback = False
        try:
            score, verdict, explanation = await call_provider(provider, active_model)
        except Exception as primary_err:
            if fallback_active:
                fb_model = model_for(fallback_provider)
                logging.warning(f"⚠️ Provider {provider} ({active_model}) failed for offense {payload.offense_id}: {primary_err}. Fallback → {fallback_provider} ({fb_model}).")
                try:
                    score, verdict, explanation = await call_provider(fallback_provider, fb_model)
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
        note_text = f"AI Analysis ({provider_label}) | Verdict: {verdict} | Score: {score} | Reason: {explanation}"
        note_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}/notes?note_text={urllib.parse.quote(note_text)}"
        note_resp = await client.post(note_url, headers=HEADERS)
        
        if note_resp.status_code in (200, 201):
            logging.debug(f"Offense {payload.offense_id} successfully updated with note.")
            
        if score <= 0.6:
            # Низький скор → автозакриття. Не призначаємо нікого, бо офенс закриється.
            logging.debug(f"Score {score} is low. Triggering auto-close for Offense {payload.offense_id}")
            await close_qradar_offense(client, payload.offense_id, score)
        elif assignee:
            # Високий скор → офенс лишається відкритим, передаємо аналітику з prompts.json
            assign_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}?assigned_to={assignee}"
            assign_resp = await client.post(assign_url, headers=HEADERS)
            if assign_resp.status_code in (200, 201):
                logging.info(f"👤 Офенс {payload.offense_id} призначено на {assignee} (score {score} > 0.6)")
            else:
                logging.error(f"⚠️ Не вдалося призначити офенс {payload.offense_id} на {assignee}: {assign_resp.text}")

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                UPDATE offenses 
                SET status = 'PROCESSED', score = ?, verdict = ?, last_updated = CURRENT_TIMESTAMP
                WHERE offense_id = ?
            """, (score, verdict, payload.offense_id))

    logging.info(f"✅ Офенс {payload.offense_id} оброблено | Режим: {'Ручний' if payload.is_manual else 'Авто'} | Провайдер: {provider_label} | Вердикт: {verdict} | Score: {score}")
    return {"status": "success", "offense_id": payload.offense_id, "verdict": verdict, "score": score, "explanation": explanation, "provider": used_provider, "fallback": used_fallback}

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