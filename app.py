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

VERTEX_KEY_PATH = "/opt/qradar-middleware/me-vertex-ai-studio-666353d9e1df.json"
CONFIG_FILE = "/opt/qradar-middleware/config.json"
PROMPTS_FILE = "/opt/qradar-middleware/prompts.json"
PROMPTS_DIR = "/opt/qradar-middleware/prompts"
QUERIES_DIR = "/opt/qradar-middleware/queries"
# qwen2.5-coder: max 32K (надійний JSON), qwen3.5: до 256K (JSON баг з format:json)
MODELS_MAX_CTX = {
    "qwen2.5-coder:7b": 32768,
    "qwen2.5-coder:14b": 32768,
    "qwen2.5-coder:32b": 32768,
    "qwen3.5:9b": 65536,
    "qwen3.5:27b": 65536,
}
# Моделі qwen2.5-coder підтримують format:"json" надійно
MODELS_WITH_JSON_FORMAT = {"qwen2.5-coder:7b", "qwen2.5-coder:14b", "qwen2.5-coder:32b"}

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI(title="QRadar AI Middleware")

# --- ЗАВАНТАЖЕННЯ КОНФІГУРАЦІЇ ---
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load config.json: {e}")
    
    # Резервні значення на випадок відсутності файлу
    return {
        "qradar_url": "https://127.0.0.1",
        "qradar_token": "",
        "ollama_url": "http://127.0.0.1:11434",
        "fast_model": "qwen2.5-coder:7b",
        "deep_model": "qwen2.5-coder:32b",
        "timeout_seconds": 600,
        "aql_limit": 1500
    }

APP_CONFIG = load_config()

# Динамічні глобальні змінні
QRADAR_API_URL = f"{APP_CONFIG['qradar_url']}/api"
OLLAMA_API_URL = f"{APP_CONFIG['ollama_url']}/api/generate"
HEADERS = {
    "SEC": APP_CONFIG['qradar_token'],
    "Content-Type": "application/json",
    "Accept": "application/json"
}
# ---------------------------------

# Нова проста модель - приймаємо ТІЛЬКИ номер інциденту
class UniversalTrigger(BaseModel):
    offense_id: int
    is_manual: bool = False  # False = автоматика (Custom Action/Poller), True = кнопка (Web UI)

DEFAULT_PROMPT = "Analyze the following logs for malicious activity. Identify any anomalies or security threats."

# --- ДОДАЙ ЦЮ КОНСТАНТУ НА ПОЧАТКУ ФАЙЛУ (біля CONFIG_FILE) ---
PROMPTS_DIR = "/opt/qradar-middleware/prompts"

def get_dynamic_prompt(rule_name):
    """Шукає мапінг у JSON: [ 'Промпт', 'Відповідальний', 'AQL' ]"""
    default_text = "Analyze logs for malicious activity."
    default_aql = "default.aql"
    
    if not os.path.exists(PROMPTS_FILE):
        return default_text, None, default_aql
        
    try:
        with open(PROMPTS_FILE, "r", encoding="utf-8") as f:
            prompt_mapping = json.load(f)
            
        for key, config in prompt_mapping.items():
            if key.lower() in rule_name.lower():
                filename = ""
                assignee = None
                aql_file = default_aql
                
                if isinstance(config, str):
                    filename = config
                elif isinstance(config, list) and len(config) > 0:
                    filename = config[0] # Index 0: Prompt
                    if len(config) > 1 and config[1].strip():
                        assignee = config[1].strip() # Index 1: Assignee
                    if len(config) > 2 and config[2].strip():
                        aql_file = config[2].strip() # Index 2: AQL file
                        
                filepath = os.path.join(PROMPTS_DIR, filename)
                if os.path.exists(filepath):
                    with open(filepath, "r", encoding="utf-8") as pf:
                        return pf.read(), assignee, aql_file
                return default_text, None, default_aql

        # Default блок
        if "Default" in prompt_mapping:
            cfg = prompt_mapping["Default"]
            f_name = cfg[0] if isinstance(cfg, list) else cfg
            a_file = cfg[2] if isinstance(cfg, list) and len(cfg) > 2 else default_aql
            # ... завантаження файлу ...
            return prompt_text, None, a_file

    except Exception as e:
        logging.error(f"Error: {e}")
    return default_text, None, default_aql
    
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
    
    # Витягуємо ID першого правила, яке створило цей офенс
    rules = data.get("rules", [])
    rule_id = rules[0].get("id") if rules else None
    
    if offense_type_id == 0: entity_type = "SourceIP"
    elif offense_type_id == 1: entity_type = "DestinationIP"
    elif offense_type_id == 3: entity_type = "User"
    else: entity_type = "SourceIP"

    return {
        "entity_value": entity_value,
        "entity_type": entity_type,
        "offense_name": offense_name,
        "rule_id": rule_id
    }

async def fetch_data_from_qradar(client: httpx.AsyncClient, offense_id: int, time_depth: str, aql_filename: str):
    """
    Зчитує шаблон AQL з файлу та виконує точний пошук INOFFENSE.
    """
    filepath = os.path.join(QUERIES_DIR, aql_filename)
    
    # Резервний запит також тепер використовує {limit}
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

    # Отримуємо глобальний ліміт з конфігурації
    global_limit = APP_CONFIG.get("aql_limit", 1500)

    # Підставляємо динамічні змінні у шаблон, включаючи ліміт
    aql = aql_template.format(offense_id=offense_id, time_depth=time_depth, limit=global_limit)

    logging.info(f"Executing Custom AQL ({aql_filename}): {aql}")
    
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

async def update_qradar_offense(client: httpx.AsyncClient, offense_id: int, note_text: str):
    """Додає фінальну нотатку в QRadar"""
    encoded_note = urllib.parse.quote(note_text)
    note_url = f"{QRADAR_API_URL}/siem/offenses/{offense_id}/notes?note_text={encoded_note}"
    response = await client.post(note_url, headers=HEADERS)
    if response.status_code in (200, 201):
        logging.info(f"Offense {offense_id} successfully updated with note.")

async def close_qradar_offense(client: httpx.AsyncClient, offense_id: int, score: float):
    """Закриває офенс у QRadar як False Positive, якщо score <= 0.6"""
    url = f"{QRADAR_API_URL}/siem/offenses/{offense_id}"
    params = {
        "status": "CLOSED",
        "closing_reason_id": 1 
    }
    
    try:
        response = await client.post(url, headers=HEADERS, params=params)
        if response.status_code == 200:
            logging.info(f"OFFENSE {offense_id} CLOSED AUTOMATICALLY. Score ({score}) is below threshold.")
        else:
            logging.error(f"Failed to close offense {offense_id}: {response.text}")
    except Exception as e:
        logging.error(f"Error during closing offense: {e}")

async def ask_ollama(client: httpx.AsyncClient, model: str, prompt: str) -> tuple[float, str, str]:
    """Відправляє запит до локальної Ollama та повертає (score, verdict, explanation)"""
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

    response = await client.post(OLLAMA_API_URL, json=payload, timeout=600.0)
    response.raise_for_status()
    llm_text = response.json().get("response", "")

    if not llm_text.strip():
        raise ValueError("Empty response from Ollama")

    # Надійний парсинг
    json_match = re.search(r'\{[^{}]*"score"[^{}]*\}', llm_text)
    parsed_json = json.loads(json_match.group()) if json_match else json.loads(llm_text.strip())

    return (
        float(parsed_json.get("score", 0.0)),
        parsed_json.get("verdict", "Unknown"),
        parsed_json.get("explanation", "No explanation provided.")
    )

async def ask_vertex(client: httpx.AsyncClient, model: str, prompt: str) -> tuple[float, str, str]:
    """Відправляє запит до Google Cloud Vertex AI (Gemini)"""
    
    project_id = APP_CONFIG.get("vertex_project", "your-gcp-project-id")
    location = APP_CONFIG.get("vertex_location", "global")
    
    # 1. Автоматична генерація токена з JSON-ключа (ВІДНОВЛЕНО)
    try:
        credentials = service_account.Credentials.from_service_account_file(
            VERTEX_KEY_PATH,
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        auth_req = google.auth.transport.requests.Request()
        credentials.refresh(auth_req)
        token = credentials.token
    except Exception as e:
        logging.error(f"Помилка авторизації Vertex AI (перевірте JSON-ключ): {e}")
        raise ValueError("Vertex AI Auth failed")

    # 2. Формування REST API Endpoint
    if location == "global":
        host = "aiplatform.googleapis.com"
    else:
        host = f"{location}-aiplatform.googleapis.com"
        
    endpoint = f"https://{host}/v1/projects/{project_id}/locations/{location}/publishers/google/models/{model}:generateContent"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # 3. Payload
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
            "maxOutputTokens": 4096,
            "topP": 0.9,
            "presencePenalty": 0.0
        }
    }

    # 4. Відправка та обробка
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
        
    except httpx.HTTPStatusError as e:
        logging.error(f"Vertex AI API Error {e.response.status_code}: {raw_response_text}")
        raise ValueError(f"Vertex API Error: {e.response.status_code}")
    except httpx.RequestError as e:
        logging.error(f"Мережева помилка (таймаут або недоступність): {e}")
        raise ValueError("Vertex Network Error")
    except Exception as e:
        logging.error(f"Помилка парсингу відповіді Vertex AI: {e} | Сирий текст: {raw_response_text[:200]}")
        raise ValueError("Failed to parse Vertex AI response")
        
@app.post("/universal-analysis")
async def universal_analysis(payload: UniversalTrigger):
    
    # 1. Читаємо глобальний перемикач та визначаємо модель
    provider = APP_CONFIG.get("ai_provider", "ollama")
    time_depth = "LAST 7 DAYS" if payload.is_manual else "LAST 24 HOURS"

    if provider == "vertex":
        active_model = APP_CONFIG.get("vertex_deep", "gemini-1.5-pro") if payload.is_manual else APP_CONFIG.get("vertex_fast", "gemini-1.5-flash")
    else:
        active_model = APP_CONFIG.get("deep_model", "qwen3.5:27b") if payload.is_manual else APP_CONFIG.get("fast_model", "qwen2.5-coder:7b")

    logging.info(f"Запуск: Offense {payload.offense_id} | Режим: {'Ручний' if payload.is_manual else 'Авто'} | Провайдер: {provider} | Модель: {active_model}")

    async with httpx.AsyncClient(verify=False, timeout=APP_CONFIG.get("timeout_seconds", 600.0)) as client:
        
        # 2. Збираємо контекст
        details = await get_offense_details(client, payload.offense_id)
        if not details:
            raise HTTPException(status_code=404, detail="Offense not found or API error")
            
        # 3. Визначаємо промпт (строго 3 змінні)
        instruction, assignee, aql_filename = get_dynamic_prompt(details['offense_name'])

        # 4. Дістаємо події через динамічний AQL
        raw_events = await fetch_data_from_qradar(client, payload.offense_id, time_depth, aql_filename)        
        if not raw_events:
            raise HTTPException(status_code=404, detail=f"No linked events found for Offense {payload.offense_id}")

        # 5. Формуємо єдиний промпт для будь-якої моделі
        # Динамічно обрізаємо логи під контекстне вікно Ollama (Vertex з'їсть і так)
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

        # 6. Аналіз через обраного провайдера
        try:
            if provider == "vertex":
                score, verdict, explanation = await ask_vertex(client, active_model, prompt)
            else:
                score, verdict, explanation = await ask_ollama(client, active_model, prompt)
        except Exception as e:
            logging.error(f"AI Provider ({provider}) error: {e}")
            raise HTTPException(status_code=503, detail=f"{provider.capitalize()} API error or bad JSON")

        # 7. Додаємо нотатку в QRadar
        note_text = f"AI Analysis ({provider.upper()}) | Verdict: {verdict} | Score: {score} | Reason: {explanation}"
        note_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}/notes?note_text={urllib.parse.quote(note_text)}"
        note_resp = await client.post(note_url, headers=HEADERS)
        
        if note_resp.status_code in (200, 201):
            logging.info(f"Offense {payload.offense_id} successfully updated with note.")
            
        # 8. Призначення на користувача
        if assignee:
            assign_url = f"{QRADAR_API_URL}/siem/offenses/{payload.offense_id}?assigned_to={assignee}"
            assign_resp = await client.post(assign_url, headers=HEADERS)
            if assign_resp.status_code in (200, 201):
                logging.info(f"👤 Офенс {payload.offense_id} успішно призначено на користувача: {assignee}")
            else:
                logging.error(f"⚠️ Не вдалося призначити офенс {payload.offense_id} на {assignee}: {assign_resp.text}")

        # 9. Автоматичне закриття
        if score <= 0.6:
            logging.info(f"Score {score} is low. Triggering auto-close for Offense {payload.offense_id}")
            await close_qradar_offense(client, payload.offense_id, score)

    return {"status": "success", "offense_id": payload.offense_id, "verdict": verdict, "score": score, "explanation": explanation}

@app.get("/", response_class=HTMLResponse)
async def get_web_ui():
    """Спрощений і набагато зручніший Web UI"""
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

    // Відображаємо статус завантаження
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
            // Читаємо JSON відповідь від бекенду
            const data = await response.json();
            resultDiv.className = 'success';
            resultDiv.innerText = `✅ Аналіз завершено!\\nВердикт: ${data.verdict}\\nОцінка (Score): ${data.score}`;
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