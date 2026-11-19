#!/usr/bin/env python3
"""Офлайн A/B: повна відповідь локальної моделі vs компактна (compact_verdict.py) на збережених промптах.

Бере з ai_dataset.db (ai_unique.example_prompt_z) до N промптів, рівномірно за правилами (lens), і для кожного шле на llm01
два запити ПОСЛІДОВНО: A = промпт як є (повний формат), B = той самий промпт із компактним форматом
(compact_verdict.to_compact) + max_tokens. Нічого в QRadar не пише. Порівнює: токени відповіді, секунди, частку
розібраних відповідей, збіг вердикту, збіг рішення «закрити (≤0.6) / лишити».
УВАГА: llm01 паралельно обслуговує прод — абсолютні секунди завищені, відносне порівняння A/B чесне лише приблизно
(запити чергуються A,B для кожного промпту, щоб навантаження впливало на обидва однаково).

Запуск на mdlwr01: /opt/qradar-middleware/venv/bin/python tools/compact_ab.py [N] [--max-tokens 64]
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import compact_verdict  # noqa: E402

BASE = "/opt/qradar-middleware"


def pick(n: int) -> list:
    conn = sqlite3.connect(f"file:{BASE}/ai_dataset.db?mode=ro", uri=True)
    rows = conn.execute("SELECT ukey, lens, t1_verdict, t1_score, example_prompt_z FROM ai_unique "
                        "WHERE source='qradar' AND example_prompt_z IS NOT NULL ORDER BY lens, n_seen DESC").fetchall()
    by: dict = {}
    for r in rows:
        by.setdefault(r[1], []).append(r)
    out, i = [], 0
    while len(out) < n and any(by.values()):          # по колу з кожного lens
        for lens in list(by):
            if by[lens] and len(out) < n:
                out.append(by[lens].pop(0))
        i += 1
    return out


def call(cfg: dict, prompt: str, max_tokens: int = 0) -> dict:
    payload = {"model": cfg.get("fast_model", "qwen2.5-coder-3b"), "messages": [{"role": "user", "content": prompt}],
               "temperature": 0.1, "response_format": {"type": "json_object"}, "stream": False}
    if max_tokens:
        payload["max_tokens"] = max_tokens
    t0 = time.time()
    r = requests.post(cfg["openai_base"].rstrip("/") + "/chat/completions", json=payload, timeout=300)
    dt = time.time() - t0
    r.raise_for_status()
    j = r.json()
    text = j["choices"][0]["message"]["content"] or ""
    m = re.search(r'\{[^{}]*"score"[^{}]*\}', text)
    try:
        d = json.loads(m.group() if m else text.strip())
        score, verdict = float(d.get("score")), str(d.get("verdict"))
    except (ValueError, TypeError):
        score = verdict = None
    return {"sec": dt, "tok": (j.get("usage") or {}).get("completion_tokens"), "score": score, "verdict": verdict}


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    n = int(args[0]) if args else 24
    mt = int(sys.argv[sys.argv.index("--max-tokens") + 1]) if "--max-tokens" in sys.argv else 64
    cfg = json.load(open(f"{BASE}/config.json"))
    res = []
    for ukey, lens, t1v, t1s, blob in pick(n):
        prompt = zlib.decompress(blob).decode("utf-8")
        cp = compact_verdict.to_compact(prompt)
        if cp == prompt:
            print(f"{ukey[:8]} пропущено: промпт не містить стандартних рядків формату (інша версія)")
            continue
        try:
            a, b = call(cfg, prompt), call(cfg, cp, mt)
        except Exception as e:
            print(f"{ukey[:8]} помилка {type(e).__name__}")
            continue
        res.append((lens, t1v, t1s, a, b))
        print(f"{ukey[:8]} {lens[:34]:34} A {a['tok']:>3}tok {a['sec']:5.1f}s {a['verdict']} {a['score']} | B {b['tok']:>3}tok {b['sec']:5.1f}s {b['verdict']} {b['score']}", flush=True)
    if not res:
        return
    ok = [r for r in res if r[3]["score"] is not None and r[4]["score"] is not None]
    print(f"\n=== {len(res)} промптів; обидві відповіді розібрано: {len(ok)} (A {sum(r[3]['score'] is not None for r in res)}, B {sum(r[4]['score'] is not None for r in res)}) ===")
    for name, i in (("A повний", 3), ("B компактний", 4)):
        toks = [r[i]["tok"] for r in res if r[i]["tok"]]
        secs = [r[i]["sec"] for r in res]
        print(f"{name}: токенів відповіді сер. {st.mean(toks):.1f}, сек. сер. {st.mean(secs):.1f} (медіана {st.median(secs):.1f})")
    same_v = sum(r[3]["verdict"] == r[4]["verdict"] for r in ok)
    same_d = sum((r[3]["score"] <= 0.6) == (r[4]["score"] <= 0.6) for r in ok)
    print(f"збіг вердикту A/B: {same_v}/{len(ok)}; збіг рішення закрити/лишити: {same_d}/{len(ok)}; сер. |Δscore| {st.mean(abs(r[3]['score']-r[4]['score']) for r in ok):.2f}")
    print("Розбіжності в рішенні:")
    for r in ok:
        if (r[3]["score"] <= 0.6) != (r[4]["score"] <= 0.6):
            print(f"  {r[0][:40]} A {r[3]['verdict']} {r[3]['score']} / B {r[4]['verdict']} {r[4]['score']}")


if __name__ == "__main__":
    main()
