"""Черга офенсів з пріоритетом за магнітудою — таблиця `work_queue` в ai_state.db.

Навіщо: до 23.09.2026 поллер сам вибирав ≤100 офенсів на ран і одразу слав їх у
мідлваре. Порядок — «кругова роздача по юзкейсах, усередині найстаріші вперед» —
взагалі не дивився на магнітуду. Заміряно 23.09.2026: 158 відкритих injection-офенсів
(51 на mag 7), з них 150 мідлваре не бачив жодного разу — вони конкурували за 100
місць із File Decode (581), IRC (514), Botnet (281) і програвали. Тобто mag-7
lsass-інжект стояв у тій самій черзі, що й mag-2 FW-deny.

Тепер discovery і processing роз'єднані:
  продюсери (poller.py — auto; app.py /universal-analysis — manual/catchup)
  лише кладуть рядок (offense_id, magnitude, source, lens) сюди;
  консюмер (worker.py) забирає їх атомарно у порядку
      magnitude DESC → (source='manual') DESC → enqueued_at ASC
  і віддає у внутрішній /process-one.

Черга ПЕРЕСТАВЛЯЄ роботу, а не додає потужності: при сталому припливі > дренажу
росте хвіст QUEUED. Його тримає в межах sweep() — дроп low-mag рядків, старших за TTL.
Гарантія, яку ми купуємо: mag-7 більше ніколи не чекає за mag-2.

Лише stdlib. Усі функції беруть відкрите з'єднання (див. connect()) — так тести
працюють на одній :memory:-базі, а прод — на файлі. Час передається параметром
`now` (UTC 'YYYY-MM-DD HH:MM:SS', як CURRENT_TIMESTAMP у таблиці offenses), щоб
тести lease/TTL були детермінованими.
"""

import json
import sqlite3
import time

DB_PATH = "/opt/qradar-middleware/ai_state.db"

QUEUED, IN_PROGRESS, DONE, ERROR = "QUEUED", "IN_PROGRESS", "DONE", "ERROR"
SOURCES = ("auto", "manual", "catchup")

# Порядок claim'у. Один вираз, щоб claim_next() і position_of() ніколи не роз'їхались.
ORDER_BY = "magnitude DESC, (source = 'manual') DESC, enqueued_at ASC, offense_id ASC"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS work_queue (
    offense_id   INTEGER PRIMARY KEY,
    magnitude    INTEGER NOT NULL DEFAULT 0,
    source       TEXT    NOT NULL,
    lens         TEXT,
    overrides    TEXT,
    status       TEXT    NOT NULL DEFAULT 'QUEUED',
    enqueued_at  TEXT    NOT NULL,
    lease_until  TEXT,
    attempts     INTEGER NOT NULL DEFAULT 0,
    result       TEXT
);
CREATE INDEX IF NOT EXISTS wq_claim ON work_queue (status, magnitude DESC, enqueued_at);
CREATE TABLE IF NOT EXISTS queue_control (
    key    TEXT PRIMARY KEY,
    value  TEXT
);
"""


def now_utc() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def _plus(ts: str, seconds: float) -> str:
    t = time.mktime(time.strptime(ts, "%Y-%m-%d %H:%M:%S"))  # локальний mktime, але різниця не залежить від TZ
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t + seconds))


def connect(path: str = DB_PATH) -> sqlite3.Connection:
    """isolation_level=None → транзакціями керуємо самі (BEGIN IMMEDIATE у claim/enqueue).
    timeout=30 → sqlite чекає на лок замість миттєвого SQLITE_BUSY."""
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    # WAL: кілька воркерів claim'ять паралельно з тим, як app.py пише в offenses.
    # Перемикається один раз і лишається у файлі; на :memory: не працює — ігноруємо.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    conn.executescript(_SCHEMA)


def _retry_locked(fn, attempts: int = 5):
    """BEGIN IMMEDIATE може впасти з 'database is locked', якщо інший воркер саме
    claim'ить. Коротка пауза і повтор — не помилка."""
    for i in range(attempts):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            if "locked" not in str(e).lower() and "busy" not in str(e).lower():
                raise
            if i == attempts - 1:
                raise
            time.sleep(0.2 * (i + 1))


def get_status(conn: sqlite3.Connection, offense_id: int):
    row = conn.execute("SELECT status FROM work_queue WHERE offense_id = ?", (offense_id,)).fetchone()
    return row["status"] if row else None


def enqueue(conn: sqlite3.Connection, offense_id: int, magnitude: int, source: str,
            lens: str | None = None, overrides: dict | None = None,
            force: bool = False, now: str | None = None) -> str:
    """Кладе офенс у чергу. Повертає, що сталося:
      'inserted'  — новий рядок;
      'refreshed' — уже QUEUED, оновили магнітуду (вона могла зрости, поки чекав);
      'requeued'  — був DONE/ERROR і force=True → знову QUEUED з нуля;
      'skipped'   — уже QUEUED (без змін магнітуди), IN_PROGRESS, або DONE/ERROR без force.
    IN_PROGRESS ніколи не чіпаємо — воркер якраз його обробляє."""
    if source not in SOURCES:
        raise ValueError(f"source має бути одним з {SOURCES}, отримано {source!r}")
    now = now or now_utc()
    ov = json.dumps(overrides, ensure_ascii=False) if overrides else None

    def tx():
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT status, magnitude FROM work_queue WHERE offense_id = ?",
                               (offense_id,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO work_queue (offense_id, magnitude, source, lens, overrides, status, enqueued_at) "
                    "VALUES (?, ?, ?, ?, ?, 'QUEUED', ?)",
                    (offense_id, int(magnitude), source, lens, ov, now))
                outcome = "inserted"
            elif row["status"] == QUEUED:
                if int(row["magnitude"]) != int(magnitude):
                    conn.execute("UPDATE work_queue SET magnitude = ? WHERE offense_id = ?",
                                 (int(magnitude), offense_id))
                    outcome = "refreshed"
                else:
                    outcome = "skipped"
            elif force and row["status"] in (DONE, ERROR):
                conn.execute(
                    "UPDATE work_queue SET status = 'QUEUED', magnitude = ?, source = ?, lens = ?, "
                    "overrides = ?, enqueued_at = ?, lease_until = NULL, attempts = 0, result = NULL "
                    "WHERE offense_id = ?",
                    (int(magnitude), source, lens, ov, now, offense_id))
                outcome = "requeued"
            else:
                outcome = "skipped"
            conn.execute("COMMIT")
            return outcome
        except Exception:
            conn.execute("ROLLBACK")
            raise

    return _retry_locked(tx)


def claim_next(conn: sqlite3.Connection, lease_seconds: float = 900, now: str | None = None):
    """Атомарно забирає наступний офенс: QUEUED або IN_PROGRESS із простроченою
    орендою (воркер упав — рядок повертається в чергу сам). Повертає dict або None."""
    now = now or now_utc()
    lease_until = _plus(now, lease_seconds)

    def tx():
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT offense_id, magnitude, source, lens, overrides, attempts FROM work_queue "
                "WHERE status = 'QUEUED' OR (status = 'IN_PROGRESS' AND lease_until < ?) "
                f"ORDER BY {ORDER_BY} LIMIT 1",
                (now,)).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            conn.execute(
                "UPDATE work_queue SET status = 'IN_PROGRESS', lease_until = ?, attempts = attempts + 1 "
                "WHERE offense_id = ?",
                (lease_until, row["offense_id"]))
            conn.execute("COMMIT")
            return {
                "offense_id": row["offense_id"],
                "magnitude": row["magnitude"],
                "source": row["source"],
                "lens": row["lens"],
                "overrides": json.loads(row["overrides"]) if row["overrides"] else {},
                "attempts": row["attempts"] + 1,
            }
        except Exception:
            conn.execute("ROLLBACK")
            raise

    return _retry_locked(tx)


def mark(conn: sqlite3.Connection, offense_id: int, status: str, result: dict | str | None = None) -> None:
    if status not in (DONE, ERROR, QUEUED):
        raise ValueError(f"mark: недопустимий статус {status!r}")
    res = result if (result is None or isinstance(result, str)) else json.dumps(result, ensure_ascii=False)
    conn.execute("UPDATE work_queue SET status = ?, result = ?, lease_until = NULL WHERE offense_id = ?",
                 (status, res, offense_id))


def position_of(conn: sqlite3.Connection, offense_id: int):
    """Скільки QUEUED-рядків воркер забере ПЕРЕД цим. 0 = наступний. None = не в черзі/не QUEUED."""
    row = conn.execute("SELECT magnitude, source, enqueued_at, status FROM work_queue WHERE offense_id = ?",
                       (offense_id,)).fetchone()
    if row is None or row["status"] != QUEUED:
        return None
    m, is_manual, t = row["magnitude"], 1 if row["source"] == "manual" else 0, row["enqueued_at"]
    return conn.execute(
        "SELECT COUNT(*) FROM work_queue WHERE status = 'QUEUED' AND ("
        "  magnitude > ? OR"
        "  (magnitude = ? AND (source = 'manual') > ?) OR"
        "  (magnitude = ? AND (source = 'manual') = ? AND (enqueued_at < ? OR (enqueued_at = ? AND offense_id < ?)))"
        ")",
        (m, m, is_manual, m, is_manual, t, t, offense_id)).fetchone()[0]


def status_of(conn: sqlite3.Connection, offense_id: int):
    row = conn.execute("SELECT * FROM work_queue WHERE offense_id = ?", (offense_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["overrides"] = json.loads(d["overrides"]) if d["overrides"] else {}
    if d["result"]:
        try:
            d["result"] = json.loads(d["result"])
        except ValueError:
            pass
    d["position"] = position_of(conn, offense_id)
    return d


def depth(conn: sqlite3.Connection) -> dict:
    out = {QUEUED: 0, IN_PROGRESS: 0, DONE: 0, ERROR: 0, "by_magnitude": {}}
    for r in conn.execute("SELECT status, COUNT(*) c FROM work_queue GROUP BY status"):
        out[r["status"]] = r["c"]
    for r in conn.execute("SELECT magnitude, COUNT(*) c FROM work_queue WHERE status = 'QUEUED' "
                          "GROUP BY magnitude ORDER BY magnitude DESC"):
        out["by_magnitude"][int(r["magnitude"])] = r["c"]
    return out


# --- hold: «не бери нових офенсів, llm01 потрібен людині» -------------------------------
# У llama.cpp один слот. Коли аналітик пише в пісочницю (/chat), app.py ставить hold на
# кілька десятків секунд; воркер перед кожним claim'ом дивиться сюди і, поки hold
# активний, нових офенсів не бере — ті, що вже в /process-one, дороблюються, і наступний
# слот дістається людині. Hold завжди з дедлайном, тож «застрягти» він не може.

def set_hold(conn: sqlite3.Connection, key: str, seconds: float, now: str | None = None) -> str:
    until = _plus(now or now_utc(), seconds)
    conn.execute("INSERT INTO queue_control (key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (f"hold:{key}", until))
    return until


def hold_until(conn: sqlite3.Connection, key: str):
    row = conn.execute("SELECT value FROM queue_control WHERE key = ?", (f"hold:{key}",)).fetchone()
    return row["value"] if row else None


def hold_active(conn: sqlite3.Connection, key: str, now: str | None = None) -> bool:
    until = hold_until(conn, key)
    return bool(until) and until > (now or now_utc())


def sweep(conn: sqlite3.Connection, low_mag_max: int, ttl_days: float,
          done_retention_days: float, now: str | None = None) -> tuple[int, int]:
    """(1) дроп QUEUED хвоста: magnitude ≤ low_mag_max і старші за ttl_days — це шум,
    який дренаж не встигає, і чекати він може вічно; (2) чистка DONE/ERROR старших за
    done_retention_days. Повертає (dropped_queued, purged_done). High-mag не чіпає ніколи."""
    now = now or now_utc()
    cut_q = _plus(now, -ttl_days * 86400)
    cut_d = _plus(now, -done_retention_days * 86400)
    a = conn.execute("DELETE FROM work_queue WHERE status = 'QUEUED' AND magnitude <= ? AND enqueued_at < ?",
                     (int(low_mag_max), cut_q)).rowcount
    b = conn.execute("DELETE FROM work_queue WHERE status IN ('DONE','ERROR') AND enqueued_at < ?",
                     (cut_d,)).rowcount
    return a, b
