"""Журнал навчальних прикладів: що саме бачила модель і що відповіла.

Навіщо: ai_state.db зберігає лише offense_id/score/verdict — без промпту й подій.
Для будь-якої майбутньої дистиляції/оцінки меншої моделі потрібен точний вхід.
Окремий файл ai_dataset.db (не ai_state.db), щоб не роздувати робочу БД і не
конкурувати за її блокування. Лише stdlib. Збій запису НІКОЛИ не ламає обробку
офенсу (виклик обгорнутий у try/except в app.py).

Колонка human_outcome заповнюється окремо (повторне відкриття / ручне закриття
аналітиком) — тут лишається NULL.
"""
import sqlite3
import zlib

DDL = """
CREATE TABLE IF NOT EXISTS ai_dataset (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    offense_id INTEGER,
    description TEXT,
    lens TEXT,
    mode TEXT,
    events_n INTEGER,
    prompt_chars INTEGER,
    prompt_z BLOB,
    t1_provider TEXT,
    t1_model TEXT,
    t1_score REAL,
    t1_verdict TEXT,
    t1_explanation TEXT,
    t1_mitigated INTEGER,
    escalated INTEGER,
    final_score REAL,
    final_verdict TEXT,
    human_outcome TEXT
)
"""
IDX = "CREATE INDEX IF NOT EXISTS ix_ai_dataset_offense ON ai_dataset(offense_id)"


def log_example(path, config, *, offense_id, description, lens, mode, events_n,
                prompt, t1, escalated, final_score, final_verdict):
    """t1 = (provider, model, score, verdict, explanation, mitigated)."""
    if not config.get("ai_dataset_enabled", True):
        return
    max_rows = int(config.get("ai_dataset_max_rows", 150000))
    blob = zlib.compress((prompt or "").encode("utf-8"), 6)
    with sqlite3.connect(path, timeout=10) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(DDL)
        conn.execute(IDX)
        cur = conn.execute(
            "INSERT INTO ai_dataset (offense_id, description, lens, mode, events_n, prompt_chars, prompt_z,"
            " t1_provider, t1_model, t1_score, t1_verdict, t1_explanation, t1_mitigated,"
            " escalated, final_score, final_verdict) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (offense_id, (description or "")[:300], lens, mode, events_n, len(prompt or ""), blob,
             t1[0], t1[1], t1[2], t1[3], (t1[4] or "")[:1500], 1 if t1[5] else 0,
             1 if escalated else 0, final_score, final_verdict),
        )
        # Кільцевий буфер: кожні ~500 записів підрізаємо найстаріші понад max_rows.
        if cur.lastrowid and cur.lastrowid % 500 == 0 and max_rows > 0:
            conn.execute("DELETE FROM ai_dataset WHERE id <= ?", (cur.lastrowid - max_rows,))
