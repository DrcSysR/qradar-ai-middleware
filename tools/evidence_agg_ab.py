#!/usr/bin/env python3
"""Офлайн A/B агрегації доказів (evidence_agg) на збережених випадках датасету.

Для кожного випадку lens-ів, де логи в збереженому промпті ОБРІЗАНО (список подій не закінчується `}]`):
  A = збережений промпт як є (рівно те, що бачила модель у проді);
  B = той самий промпт, але блок логів замінено на evidence_agg.render(сирі події, той самий бюджет).
Сирі події тягнуться з QRadar заново (AQL лінзи, LAST N DAYS) — тому беруться лише недавні офенси
(example_ref ≥ MIN_ID), старі повернуть порожньо й пропускаються. Обидва промпти шлються на llm01
ПОСЛІДОВНО (A, B), A ще раз перераховується — це «шум» самої моделі (temperature 0.1) для порівняння.
Нічого в QRadar не пишеться; пошуки Ariel видаляються після читання.

Запуск на mdlwr01 (потрібні читання ai_dataset.db і config.json → від qmiddleware):
  runuser -u qmiddleware -- /opt/qradar-middleware/venv/bin/python tools/evidence_agg_ab.py [N] [--min-id 2185000] [--list]
"""
import json
import os
import re
import sqlite3
import statistics as st
import sys
import time
import zlib

import requests
import urllib3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import evidence_agg  # noqa: E402

urllib3.disable_warnings()
BASE = "/opt/qradar-middleware"
START, END = "--- START OF LOGS ---\n", "\n--- END OF LOGS ---"
CTX, CHARS_PER_TOK, OUT_RESERVE = 8192, 2.0, 1024


def arg(name, default):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def pick(n, min_id):
    cfg_prompts = json.load(open(f"{BASE}/prompts.json"))
    conn = sqlite3.connect(f"file:{BASE}/ai_dataset.db?mode=ro", uri=True)
    rows = conn.execute("SELECT ukey, lens, example_ref, example_prompt_z, claude_label FROM ai_unique "
                        "WHERE source='qradar' AND example_prompt_z IS NOT NULL ORDER BY n_seen DESC").fetchall()
    out = []
    for ukey, lens, ref, blob, label in rows:
        try:
            if int(ref) < min_id:
                continue
        except (TypeError, ValueError):
            continue
        entry = cfg_prompts.get(lens)
        if not isinstance(entry, list) or len(entry) < 3:
            continue
        prompt = zlib.decompress(blob).decode("utf-8")
        if START not in prompt or END not in prompt:
            continue
        logs = prompt.split(START, 1)[1].split(END, 1)[0]
        if logs.rstrip().endswith("]"):          # не обрізано — A/B нічого не покаже
            continue
        out.append(dict(ukey=ukey, lens=lens, ref=ref, aql=entry[2], prompt=prompt, label=label, logs_len=len(logs)))
    by = {}
    for c in out:                                  # по колу з кожної лінзи
        by.setdefault(c["lens"], []).append(c)
    res = []
    while len(res) < n and any(by.values()):
        for k in list(by):
            if by[k] and len(res) < n:
                res.append(by[k].pop(0))
    return res


def fetch_events(cfg, aql_file, offense_id):
    t = open(f"{BASE}/queries/{aql_file}", encoding="utf-8").read()
    t = re.sub(r"--[^\n]*", "", t)
    q = t.format(offense_id=offense_id, time_depth="LAST 5 DAYS", limit=cfg.get("aql_limit", 1500), source_ip="", username="")
    q = re.sub(r"\s*\n\s*", " ", q).strip()
    base = cfg["qradar_url"].rstrip("/")
    h = {"SEC": cfg["qradar_token"], "Version": "12.0", "Accept": "application/json"}
    r = requests.post(base + "/api/ariel/searches", headers=h, data={"query_expression": q}, verify=False)
    r.raise_for_status()
    sid, s = r.json()["search_id"], {}
    for _ in range(90):
        s = requests.get(f"{base}/api/ariel/searches/{sid}", headers=h, verify=False).json()
        if s.get("status") in ("COMPLETED", "ERROR", "CANCELED"):
            break
        time.sleep(2)
    ev = []
    if s.get("status") == "COMPLETED":
        ev = requests.get(f"{base}/api/ariel/searches/{sid}/results", headers=h, verify=False).json().get("events", [])
    requests.delete(f"{base}/api/ariel/searches/{sid}", headers=h, verify=False)
    return ev


def call(cfg, prompt):
    payload = {"model": cfg.get("fast_model", "qwen2.5-coder-3b"), "messages": [{"role": "user", "content": prompt}],
               "temperature": 0.1, "response_format": {"type": "json_object"}, "stream": False}
    t0 = time.time()
    r = requests.post(cfg["openai_base"].rstrip("/") + "/chat/completions", json=payload, timeout=300)
    r.raise_for_status()
    text = r.json()["choices"][0]["message"]["content"] or ""
    m = re.search(r'\{[^{}]*"score"[^{}]*\}', text)
    try:
        d = json.loads(m.group() if m else text.strip())
        return {"score": float(d.get("score")), "verdict": str(d.get("verdict")), "sec": time.time() - t0}
    except (ValueError, TypeError):
        return {"score": None, "verdict": None, "sec": time.time() - t0}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 20
    min_id = int(arg("--min-id", 2185000))
    cases = pick(n, min_id)
    if "--list" in sys.argv:
        for c in cases:
            print(c["ref"], c["lens"][:50], c["aql"], "logs", c["logs_len"], c["label"])
        print(len(cases), "кандидатів")
        return
    cfg = json.load(open(f"{BASE}/config.json"))
    res = []
    for c in cases:
        try:
            ev = fetch_events(cfg, c["aql"], c["ref"])
        except Exception as e:
            print(c["ref"], "AQL помилка", type(e).__name__)
            continue
        if not ev:
            print(c["ref"], "порожньо в вікні — пропуск")
            continue
        prompt = c["prompt"]
        head, rest = prompt.split(START, 1)
        old_logs, tail = rest.split(END, 1)
        overhead = len(prompt) - len(old_logs)
        max_chars = max(500, int((CTX - OUT_RESERVE) * CHARS_PER_TOK) - overhead)
        new_logs = evidence_agg.render(ev, max_chars)
        pb = head + START + new_logs + END + tail
        try:
            a1, a2, b = call(cfg, prompt), call(cfg, prompt), call(cfg, pb)
        except Exception as e:
            print(c["ref"], "llm помилка", type(e).__name__)
            continue
        res.append((c, len(ev), len(old_logs), len(new_logs), a1, a2, b))
        f = lambda r: f"{r['verdict']} {r['score']}"  # noqa: E731
        print(f"{c['ref']} {c['lens'][:30]:30} ev={len(ev):4} logsA={len(old_logs):5} logsB={len(new_logs):5} | A1 {f(a1)} | A2 {f(a2)} | B {f(b)} | claude {c['label']}", flush=True)
    ok = [r for r in res if None not in (r[4]["score"], r[5]["score"], r[6]["score"])]
    if not ok:
        return
    close = lambda x: x["score"] <= 0.6  # noqa: E731
    print(f"\n=== {len(res)} випадків, розібрано {len(ok)} ===")
    print(f"шум моделі (A1 vs A2): рішення збігається {sum(close(r[4]) == close(r[5]) for r in ok)}/{len(ok)}, "
          f"сер. |Δscore| {st.mean(abs(r[4]['score'] - r[5]['score']) for r in ok):.2f}")
    print(f"A1 vs B: рішення збігається {sum(close(r[4]) == close(r[6]) for r in ok)}/{len(ok)}, "
          f"сер. |Δscore| {st.mean(abs(r[4]['score'] - r[6]['score']) for r in ok):.2f}; "
          f"B гірший за A: лишити(>0.6) де A закривав {sum((not close(r[6])) and close(r[4]) for r in ok)}, "
          f"закрити де A лишав {sum(close(r[6]) and not close(r[4]) for r in ok)}")
    for name, i in (("A1", 4), ("B", 6)):
        agree = [(r[i]["score"] > 0.6) == str(r[0]["label"]).startswith("review") for r in ok if r[0]["label"]]
        print(f"{name} vs мітка Claude (слабкий орієнтир, не еталон): збіг {sum(agree)}/{len(agree)}")


if __name__ == "__main__":
    main()
