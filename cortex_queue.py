"""Кейси Cortex XDR у спільній черзі work_queue разом з офенсами QRadar.

Навіщо: до цього офенси оброблялись воркером за magnitude, а Cortex — раз на добу о 09:30 одним пакетом. Тепер
кейс — такий самий рядок черги (ключ = -incident_id, source='cortex', magnitude = мапа severity → magnitude з
config `cortex_queue_severity_magnitude`), і воркер бере наступний за пріоритетом із ОБОХ джерел.

  produce(config, conn)  — викликає poller.py (кожні 10 хв) за прапорцем `cortex_queue_enabled`: кладе нові кейси.
  process(config, claim) — викликає worker.py: розбір ОДНОГО кейсу тим самим кодом, що й 09:30
                           (cortex_incident_triage.run_triage з incidents=[inc]): закрити шум / призначити /
                           розбір Vertex / нотатка / кореляція з QRadar. Поважає `cortex_incident_dry_run`.

Модуль без побічних ефектів при імпорті (логування — з main() скриптів), тож безпечний для воркера й поллера.
Запобіжники: `cortex_queue_max_per_run`, `cortex_queue_daily_cap` (нових рядків за добу), кейс обробляється один раз
(DONE без force не повторюється; dry-run-результат після вмикання apply переставляється в чергу).
"""
import logging
import time

import cortex_incident_triage as ci
import queue_db

GONE = "gone"          # кейс уже не в потрібному статусі (закрила людина / інше правило) — нічого робити


def magnitude_for(config: dict, severity) -> int:
    m = ci.cfg(config, "cortex_queue_severity_magnitude") or {}
    try:
        return int(m.get(str(severity or "").lower(), 0))
    except (TypeError, ValueError):
        return 0


def queue_dry_run(config: dict) -> bool:
    """Черга пише в Cortex лише коли ОБИДВА прапорці вимкнені: власний `cortex_queue_dry_run` (типово true) і
    загальний `cortex_incident_dry_run`. Так чергу можна обкатати в dry-run, не чіпаючи live-режим 09:30."""
    return bool(ci.cfg(config, "cortex_queue_dry_run")) or bool(ci.cfg(config, "cortex_incident_dry_run"))


def fetch_one(config: dict, incident_id: int) -> dict | None:
    """Свіжий стан одного кейсу з Cortex. None = API недоступний; {} = кейсу немає в потрібних статусах."""
    statuses = list(ci.cfg(config, "cortex_incident_statuses"))
    reply = ci.post(config, "/public_api/v1/incidents/get_incidents", {
        "filters": [{"field": "incident_id_list", "operator": "in", "value": [str(incident_id)]},
                    {"field": "status", "operator": "in", "value": statuses}],
        "search_from": 0, "search_to": 1})
    if reply is None:
        return None
    rows = reply.get("incidents") or []
    return rows[0] if rows else {}


def _recent(conn, hours: float) -> int:
    cut = queue_db._plus(queue_db.now_utc(), -hours * 3600)
    return conn.execute("SELECT COUNT(*) FROM work_queue WHERE source='cortex' AND enqueued_at >= ?",
                        (cut,)).fetchone()[0]


def produce(config: dict, conn) -> dict:
    """Кладе нові кейси Cortex у чергу. → лічильники для логу. Нічого не пише в Cortex."""
    stats = {"inserted": 0, "requeued": 0, "skipped": 0, "capped": 0}
    if not ci.cfg(config, "cortex_queue_enabled"):
        return stats
    incidents = ci.fetch_incidents(config, list(ci.cfg(config, "cortex_incident_statuses")),
                                   float(ci.cfg(config, "cortex_incident_lookback_hours")))
    if incidents is None:
        logging.error("cortex_queue: Cortex API недоступний — продюсер пропущено")
        return stats
    dry_now = queue_dry_run(config)
    per_run = int(ci.cfg(config, "cortex_queue_max_per_run"))
    daily_left = int(ci.cfg(config, "cortex_queue_daily_cap")) - _recent(conn, 24)
    for inc in incidents:                      # від нових до старих; порядок обробки далі визначає magnitude
        key = queue_db.cortex_key(inc.get("incident_id"))
        old = queue_db.status_of(conn, key)
        redo = bool(old and old["status"] == queue_db.DONE and isinstance(old.get("result"), dict)
                    and old["result"].get("dry_run") and not dry_now)     # dry-run → apply: переробити по-справжньому
        if old and not redo and old["status"] != queue_db.QUEUED:
            stats["skipped"] += 1
            continue
        if not old or redo:
            if stats["inserted"] + stats["requeued"] >= per_run or daily_left <= 0:
                stats["capped"] += 1
                continue
        out = queue_db.enqueue(conn, key, magnitude_for(config, inc.get("severity")), "cortex",
                               lens=str(inc.get("description") or "")[:80], force=redo)
        if out in ("inserted", "requeued"):
            stats[out] += 1
            daily_left -= 1
        else:
            stats["skipped"] += 1
    return stats


def process(config: dict, claim: dict) -> dict:
    """Один кейс із черги. Повертає результат для work_queue.result; виняток = рядок лишиться IN_PROGRESS
    (оренда спливе, повтор) — воркер вирішує, коли це вже ERROR."""
    iid = abs(int(claim["offense_id"]))
    inc = fetch_one(config, iid)
    if inc is None:
        raise RuntimeError("Cortex API недоступний")
    if not inc:
        return {"status": GONE, "incident_id": iid}
    dry_run = queue_dry_run(config)
    t0 = time.time()
    res = ci.run_triage(config, dry_run, 0, incidents=[inc])
    if res is None:
        raise RuntimeError("тріаж не відпрацював")
    closed = res["closed"]
    ai = (res.get("ai") or {}).get(str(iid))
    return {"status": "closed" if closed else "review", "incident_id": iid, "dry_run": res["dry_run"],
            "rule": closed[0][1] if closed else None, "verdict": (ai or {}).get("verdict"),
            "seconds": round(time.time() - t0, 1)}
