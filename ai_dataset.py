"""Журнал навчальних прикладів: нормалізована схема + лічильник унікальності.

Навіщо: ai_state.db зберігає лише offense_id/score/verdict — без входу моделі.
Для оцінки/дистиляції меншої моделі потрібен точний вхід і вердикти, але НЕ тисячі
однакових випадків (92% викликів — те саме правило з тими самими процесами).

Модель даних (окремий файл ai_dataset.db; не ai_state.db — щоб не роздувати робочу БД):
  * ai_unique  — один рядок на УНІКАЛЬНИЙ випадок. Ключ = sha1(нормалізований підпис).
                 Лічильник повторів, к-сть різних хостів, перший/останній раз, один приклад
                 промпту (zlib), вердикти tier-1 / фінальний / Vertex-суддя / людина.
  * ai_log     — легкий журнал кожного розбору (без промпту): offense_id, ukey, score.
                 Кільцевий буфер.

Підпис (нормалізація) відкидає все, що робить випадки «різними» без зміни суті: хост,
користувача, час, лічильники подій; IP → клас (внутр./зовн.); числа, GUID, довгі hex,
каталог профілю \\Users\\<хтось>\\ → маски. Джерело: 'qradar' (події AQL лінзи) або
'cortex' (алерти інциденту, поля cortex_incident_ai.FIELDS).

Лише stdlib. Збій запису НІКОЛИ не ламає обробку (виклики обгорнуті try/except).
Файл може писати і сервіс (qmiddleware), і таймери (root): після запису власник і права (660)
на БД і -wal/-shm вирівнюються, інакше root-створений -wal дає сервісу «readonly database».
"""
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import zlib

import evidence_agg

DDL_UNIQUE = """
CREATE TABLE IF NOT EXISTS ai_unique (
    ukey TEXT PRIMARY KEY,
    source TEXT,
    lens TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    n_seen INTEGER DEFAULT 1,
    n_events INTEGER DEFAULT 0,
    hosts_json TEXT,
    n_hosts INTEGER DEFAULT 0,
    signature_json TEXT,
    example_ref TEXT,
    example_prompt_z BLOB,
    t1_verdict TEXT,
    t1_score REAL,
    final_verdict TEXT,
    final_score REAL,
    vertex_verdict TEXT,
    vertex_score REAL,
    vertex_ts DATETIME,
    human_label TEXT,
    claude_label TEXT,
    claude_reason TEXT,
    claude_ts DATETIME,
    evidence_z BLOB
)
"""
DDL_LOG = """
CREATE TABLE IF NOT EXISTS ai_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    source TEXT,
    ref TEXT,
    ukey TEXT,
    mode TEXT,
    prompt_chars INTEGER,
    t1_provider TEXT,
    t1_model TEXT,
    t1_score REAL,
    t1_verdict TEXT,
    escalated INTEGER,
    final_score REAL,
    final_verdict TEXT
)
"""

# Ключі подій, що не впливають на суть випадку (порівнюємо у нижньому регістрі).
VOLATILE = {"hostname", "host", "host_name", "logsourcename", "acct", "username", "user", "user_name",
            "events", "count", "eventcount", "starttime", "endtime", "time", "firsttime", "lasttime",
            "offense_id", "event_timestamp", "action_local_ip", "action_file_sha256"}
HOST_KEYS = ("hostname", "host", "host_name", "logsourcename")
COUNT_KEYS = ("events", "count", "eventcount")

CORTEX_SIG_FIELDS = ["name", "category", "action_pretty", "source", "actor_process_image_name",
                     "actor_process_command_line", "action_process_image_name",
                     "action_process_image_command_line", "causality_actor_process_image_name",
                     "causality_actor_process_command_line", "action_file_path", "action_file_name",
                     "action_remote_port", "dst_action_external_hostname", "mitre_technique_id_and_name"]

_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_HEX = re.compile(r"\b[0-9a-f]{12,}\b")
_USER = re.compile(r"(\\users\\|/home/)[^\\/]+")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NUM = re.compile(r"\d+")


def _ip_class(m):
    try:
        ip = ipaddress.ip_address(m.group(0))
    except ValueError:
        return "<num>"
    return "<ip-int>" if (ip.is_private or ip.is_loopback or ip.is_link_local) else "<ip-ext>"


def norm_value(v) -> str:
    s = str(v).strip().lower()[:240]
    s = _USER.sub(r"\1<u>", s)
    s = _GUID.sub("<guid>", s)
    s = _HEX.sub("<hex>", s)
    s = _IP.sub(_ip_class, s)
    return _NUM.sub("#", s)


def _fit(rows, limit=8000):
    """Скільки рядків підпису влізе в limit символів JSON — без обрізання посеред рядка."""
    while rows and len(json.dumps(rows, ensure_ascii=False)) > limit:
        rows = rows[:-1]
    return rows


def _key(source, lens, rows):
    blob = json.dumps([source, lens, rows], ensure_ascii=False, sort_keys=True)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()


def signature_qradar(lens, events):
    """→ (ukey, rows, n_events, hosts). rows = унікальні нормалізовані рядки подій (≤30)."""
    seen, hosts, n_events = set(), set(), 0
    for e in events or []:
        if not isinstance(e, dict):
            continue
        low = {str(k).lower(): v for k, v in e.items()}
        for hk in HOST_KEYS:
            if low.get(hk):
                hosts.add(str(low[hk])[:80])
        for ck in COUNT_KEYS:
            try:
                n_events += int(float(low.get(ck)))
                break
            except (TypeError, ValueError):
                continue
        seen.add(tuple(sorted((k, norm_value(v)) for k, v in low.items()
                              if k not in VOLATILE and v not in (None, "", "null"))))
    rows = [list(map(list, r)) for r in sorted(seen)][:30]
    return _key("qradar", lens, rows), rows, n_events, hosts


def signature_cortex(inc, alerts):
    seen, hosts = set(), set()
    for a in alerts or []:
        if a.get("host_name"):
            hosts.add(str(a["host_name"])[:80])
        seen.add(tuple((k, norm_value(a[k])) for k in CORTEX_SIG_FIELDS if a.get(k) not in (None, "", [], {})))
    rows = [list(map(list, r)) for r in sorted(seen)][:30]
    return _key("cortex", "", rows), rows, len(alerts or []), hosts


def _open(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(DDL_UNIQUE)
    conn.execute(DDL_LOG)
    # Міграція: колонки для міток Claude (human_label лишається для людини). CREATE IF NOT EXISTS їх не додасть.
    have = {r[1] for r in conn.execute("PRAGMA table_info(ai_unique)")}
    for col, typ in (("claude_label", "TEXT"), ("claude_reason", "TEXT"), ("claude_ts", "DATETIME"), ("evidence_z", "BLOB")):
        if col not in have:
            conn.execute(f"ALTER TABLE ai_unique ADD COLUMN {col} {typ}")
    return conn


EVIDENCE_CHARS = 8000


def _evidence_blob(events, max_chars):
    """Агрегований блок доказів для тренування/розмітки (evidence_agg), zlib. Збій → None, запис не ламаємо.
    Окремо від example_prompt_z: той містить рівно те, що бачила модель tier-1 (≈500 символів подій),
    а це — картина з УСІХ подій випадку (до max_chars), формат навчання обирається при складанні датасету."""
    try:
        if not isinstance(events, list) or not events or max_chars <= 0:
            return None
        return zlib.compress(evidence_agg.render(events, max_chars).encode("utf-8"), 6)
    except Exception:
        return None


def _fix_perms(path):
    """Власник qmiddleware:qmiddleware, права 660 (файл містить користувачів і командні рядки).
    Root-таймери (cortex_xdr_scan) створюють -wal від root — перечіплюємо, щоб сервіс міг писати."""
    try:
        import pwd
        pw = pwd.getpwnam("qmiddleware")
        uid, gid = pw.pw_uid, pw.pw_gid
    except (ImportError, KeyError):
        uid = gid = None
    for suffix in ("", "-wal", "-shm"):
        f = path + suffix
        try:
            if uid is not None and os.geteuid() == 0:
                os.chown(f, uid, gid)
            os.chmod(f, 0o660)
        except OSError:
            pass


def _record(path, config, *, source, lens, ref, mode, prompt, t1, escalated, final_score,
            final_verdict, sig, evidence_z=None):
    """t1 = (provider, model, score, verdict). sig = (ukey, rows, n_events, hosts)."""
    if not config.get("ai_dataset_enabled", True):
        return None
    ukey, rows, n_events, hosts = sig
    max_rows = int(config.get("ai_dataset_max_rows", 300000))
    with _open(path) as conn:
        cur = conn.execute("SELECT hosts_json FROM ai_unique WHERE ukey=?", (ukey,))
        row = cur.fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO ai_unique (ukey, source, lens, n_events, hosts_json, n_hosts, signature_json,"
                " example_ref, example_prompt_z, t1_verdict, t1_score, final_verdict, final_score, evidence_z)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ukey, source, lens, n_events, json.dumps(sorted(hosts)[:50]), len(hosts),
                 json.dumps(_fit(rows), ensure_ascii=False), str(ref),
                 zlib.compress((prompt or "").encode("utf-8"), 6),
                 t1[3], t1[2], final_verdict, final_score, evidence_z))
        else:
            try:
                known = set(json.loads(row[0] or "[]"))
            except ValueError:
                known = set()
            known |= hosts
            conn.execute(
                "UPDATE ai_unique SET n_seen=n_seen+1, n_events=n_events+?, last_seen=CURRENT_TIMESTAMP,"
                " hosts_json=?, n_hosts=?, t1_verdict=?, t1_score=?, final_verdict=?, final_score=?,"
                " evidence_z=COALESCE(evidence_z, ?) WHERE ukey=?",
                (n_events, json.dumps(sorted(known)[:50]), len(known), t1[3], t1[2],
                 final_verdict, final_score, evidence_z, ukey))
        c = conn.execute(
            "INSERT INTO ai_log (source, ref, ukey, mode, prompt_chars, t1_provider, t1_model, t1_score,"
            " t1_verdict, escalated, final_score, final_verdict) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (source, str(ref), ukey, mode, len(prompt or ""), t1[0], t1[1], t1[2], t1[3],
             1 if escalated else 0, final_score, final_verdict))
        if c.lastrowid and c.lastrowid % 500 == 0 and max_rows > 0:
            conn.execute("DELETE FROM ai_log WHERE id <= ?", (c.lastrowid - max_rows,))
    _fix_perms(path)
    return ukey


def log_example(path, config, *, offense_id, lens, mode, events, prompt, t1, escalated,
                final_score, final_verdict):
    """QRadar-офенс. t1 = (provider, model, score, verdict, explanation, mitigated)."""
    sig = signature_qradar(lens, events)
    return _record(path, config, source="qradar", lens=lens, ref=offense_id, mode=mode, prompt=prompt,
                   t1=t1, escalated=escalated, final_score=final_score, final_verdict=final_verdict, sig=sig,
                   evidence_z=_evidence_blob(events, int(config.get("ai_dataset_evidence_chars", EVIDENCE_CHARS))))


def log_cortex(path, config, *, incident, alerts, prompt, model, verdict, score=None):
    """Cortex-інцидент: verdict = benign|suspicious|malicious|unclear (від Vertex)."""
    sig = signature_cortex(incident, alerts)
    t1 = ("vertex", model, score, verdict)
    return _record(path, config, source="cortex", lens="", ref=incident.get("incident_id"), mode="auto",
                   prompt=prompt, t1=t1, escalated=False, final_score=score, final_verdict=verdict, sig=sig)
