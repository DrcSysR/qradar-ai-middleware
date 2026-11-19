"""Суддя Vertex для унікальних випадків датасету (ai_dataset.db → ai_unique).

Для кожного УНІКАЛЬНОГО випадку (а не кожного офенсу) з джерела 'qradar', що ще не має вердикту Vertex, бере
збережений приклад промпту (рівно те, що бачила локальна модель) і віддає його у Vertex (`ai_dataset_judge_model`,
типово `vertex_deep`, інакше `escalate_model`). Результат пишеться в `vertex_verdict/vertex_score/vertex_ts` —
НІЧОГО в QRadar не змінюється, офенси не чіпаються. Cortex-випадки пропускаються: їхній tier-1 і так Vertex.

Черговість: спершу «сіра зона» tier-1 (score 0.3–0.7: тут моделі найчастіше розходяться), потім найчастіші випадки.
Ліміт за запуск `ai_dataset_judge_max_per_run` (60) тримає вартість у межах копійок на добу.

Підсумок у журналі: скільки збіглось у рішенні «закрити (≤0.6) / лишити», і перелік розбіжностей — це перші кандидати
для ручної розмітки контрольного набору. Вердикт Vertex — НЕ еталон (він теж помиляється й не знає наших санкціонованих
програм); еталоном стає лише ручна розмітка.

Запуск: `python3 ai_dataset_judge.py [--dry-run] [--max N]` (systemd timer, раз на добу). Лише читання/запис ai_dataset.db.
"""
import argparse
import fcntl
import json
import logging
import os
import sqlite3
import sys
import time
import zlib

import requests

import ai_dataset

BASE_DIR = "/opt/qradar-middleware"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DATASET_DB = os.path.join(BASE_DIR, "ai_dataset.db")
LOCK_FILE = os.path.join(BASE_DIR, "ai_dataset_judge.lock")
LOG_FILE = os.path.join(BASE_DIR, "ai_dataset_judge.log")
VERTEX_KEY_PATH = os.path.join(BASE_DIR, "me-vertex-ai-studio-666353d9e1df.json")

DEFAULTS = {
    "ai_dataset_judge_max_per_run": 60,
    "ai_dataset_judge_model": "",
    "ai_dataset_judge_pause_seconds": 1.0,
}


def setup_logging() -> None:
    handlers = [logging.StreamHandler()]
    if os.access(BASE_DIR, os.W_OK):
        handlers.insert(0, logging.FileHandler(LOG_FILE))
    logging.basicConfig(level=logging.INFO, handlers=handlers, format="%(asctime)s - %(levelname)s - %(message)s")


def load_config() -> dict:
    with open(CONFIG_FILE, encoding="utf-8") as fh:
        return json.load(fh)


def opt(config: dict, key: str):
    v = config.get(key)
    return DEFAULTS[key] if v in (None, "") else v


def to_bool(v) -> bool:
    return v if isinstance(v, bool) else str(v).strip().lower() in ("1", "true", "yes")


def ask_vertex(config: dict, model: str, prompt: str, timeout: float = 180.0):
    """→ (score, verdict, mitigated) або None. Той самий запит, що й app.ask_vertex, без FastAPI-залежностей."""
    import google.auth.transport.requests
    from google.oauth2 import service_account
    project = config.get("vertex_project") or ""
    if not project:
        logging.error("vertex_project не задано")
        return None
    location = config.get("vertex_location") or "global"
    host = "aiplatform.googleapis.com" if location == "global" else f"{location}-aiplatform.googleapis.com"
    try:
        creds = service_account.Credentials.from_service_account_file(
            VERTEX_KEY_PATH, scopes=["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(google.auth.transport.requests.Request())
    except Exception as e:
        logging.error(f"автентифікація Vertex: {type(e).__name__}")
        return None
    url = f"https://{host}/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent"
    payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
               "generationConfig": {"responseMimeType": "application/json", "temperature": 0.1,
                                    "maxOutputTokens": 4096, "topP": 0.9}}
    for attempt in (1, 2, 3):
        try:
            r = requests.post(url, headers={"Authorization": f"Bearer {creds.token}"}, json=payload, timeout=timeout)
        except requests.RequestException as e:
            logging.error(f"Vertex недоступний: {type(e).__name__}")
            return None
        if r.status_code in (429, 500, 502, 503, 504) and attempt < 3:
            time.sleep(3 * attempt)
            continue
        if r.status_code != 200:
            logging.error(f"Vertex HTTP {r.status_code}: {r.text[:200]}")
            return None
        try:
            parts = r.json()["candidates"][0]["content"]["parts"]
            d = json.loads("".join(p.get("text", "") for p in parts if not p.get("thought")))
            if isinstance(d, list):
                d = d[0] if d else {}
            return float(d.get("score", 0.0)), str(d.get("verdict") or "Unknown")[:80], to_bool(d.get("mitigated", False))
        except (ValueError, KeyError, IndexError, TypeError):
            logging.error("неочікувана відповідь Vertex")
            return None
    return None


def pick(conn, limit: int) -> list:
    return conn.execute(
        "SELECT ukey, lens, n_seen, t1_verdict, t1_score, example_prompt_z FROM ai_unique "
        "WHERE source='qradar' AND vertex_verdict IS NULL AND example_prompt_z IS NOT NULL "
        "ORDER BY CASE WHEN t1_score BETWEEN 0.3 AND 0.7 THEN 0 ELSE 1 END, n_seen DESC, first_seen LIMIT ?",
        (limit,)).fetchall()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--max", type=int, default=0)
    args = ap.parse_args()
    setup_logging()
    lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        logging.warning("уже виконується — вихід")
        return 0
    config = load_config()
    limit = args.max or int(opt(config, "ai_dataset_judge_max_per_run"))
    model = opt(config, "ai_dataset_judge_model") or config.get("vertex_deep") or config.get("escalate_model", "")
    if not model:
        logging.error("не задано модель (ai_dataset_judge_model / vertex_deep / escalate_model)")
        return 1
    with ai_dataset._open(DATASET_DB) as conn:
        todo = pick(conn, limit)
        pending = conn.execute("SELECT COUNT(*) FROM ai_unique WHERE source='qradar' AND vertex_verdict IS NULL").fetchone()[0]
        logging.info(f"=== judge: до розгляду {len(todo)} з {pending} непідтверджених унікальних; модель {model}"
                     f"{' [dry-run]' if args.dry_run else ''} ===")
        if args.dry_run:
            for ukey, lens, n, v, s, _ in todo[:15]:
                logging.info(f"  {ukey[:8]} n={n} t1={v} {s} | {lens[:50]}")
            return 0
        agree = disagree = failed = 0
        diffs = []
        for ukey, lens, n, t1v, t1s, blob in todo:
            res = ask_vertex(config, model, zlib.decompress(blob).decode("utf-8"))
            if res is None:
                failed += 1
                continue
            vs, vv, _mit = res
            conn.execute("UPDATE ai_unique SET vertex_verdict=?, vertex_score=?, vertex_ts=CURRENT_TIMESTAMP WHERE ukey=?",
                         (vv, vs, ukey))
            conn.commit()
            t1_close, v_close = float(t1s or 0) <= 0.6, vs <= 0.6
            if t1_close == v_close:
                agree += 1
            else:
                disagree += 1
                diffs.append((ukey[:8], n, lens[:40], t1v, t1s, vv, vs))
            time.sleep(float(opt(config, "ai_dataset_judge_pause_seconds")))
    logging.info(f"=== judge: збіглись у рішенні закрити/лишити {agree}, розійшлись {disagree}, помилок Vertex {failed} ===")
    for d in diffs[:20]:
        logging.info(f"  РОЗБІЖНІСТЬ {d[0]} n={d[1]} | {d[2]} | tier-1 {d[3]} {d[4]} → Vertex {d[5]} {d[6]}")
    ai_dataset._fix_perms(DATASET_DB)
    return 0


if __name__ == "__main__":
    sys.exit(main())
