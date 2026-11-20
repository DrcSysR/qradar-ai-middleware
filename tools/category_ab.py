#!/usr/bin/env python3
"""Офлайн тест C: «категорія + дані» замість довгої інструкції use-case (на збережених випадках, llm01).

A = збережений промпт як є (довга інструкція лінзи + ≈500 символів подій).
C = той самий каркас (хедер читання доказів, активи, спільна рубрика/правила JSON), але:
      * `Task: <довга інструкція лінзи>` замінено рядком категорії + 2-3 речення загальних орієнтирів (CATEGORIES);
      * блок логів = evidence_agg.render(сирі події, ВЕСЬ звільнений бюджет) — докази з усіх подій, а не 500 символів.
Сирі події тягнуться з QRadar заново (AQL лінзи, LAST 5 DAYS) — лише недавні офенси; пошуки Ariel видаляються.
Вердикт-рядки лінз у C не порівнюються (вони визначались інструкцією) — порівнюється рішення за score
(закрити ≤0.6 / лишити >0.6) і частка смуги 0.4–0.6 («inconclusive»).
Ґрунтової істини немає: збіг із мітками Claude (правила) — лише слабкий орієнтир.
Thread Injection виключено: A у складених офенсах бачить рядки інших лінз, а тест тягне лише лінзу основного правила.

Запуск на mdlwr01 (від qmiddleware): python3 category_ab.py [N] [--min-id 2185000] [--list]
"""
import json
import os
import statistics as st
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import evidence_agg  # noqa: E402
import evidence_agg_ab as ab  # noqa: E402

START, END = ab.START, ab.END

# Категорії → загальні орієнтири (НЕ специфіка лінзи: без імен процесів/хостів середовища).
CATEGORIES = {
    "fw_denies": (
        "Category: FIREWALL DENY BURST. A host or segment produced many connections that the firewall denied. "
        "Usually harmless: multicast/broadcast/discovery chatter, a misconfigured or sleeping client, traffic the "
        "firewall already stopped. Raise the score only for a real sweep of MANY distinct internal destinations or "
        "ports from one internal host, or for a denied pattern followed by an allowed one."),
    "endpoint_chain": (
        "Category: ENDPOINT PROCESS/FILE CHAIN. A rule linked several endpoint events on one host (file created or "
        "downloaded, process launched, registry change). Usually harmless: a known application updating itself, "
        "installers, office/browser helpers, admin tooling run by its owner. Raise the score for scripting engines or "
        "living-off-the-land binaries launching from user-writable or temp paths, mass file creation, or an unknown "
        "binary with network/persistence activity."),
    "beacon": (
        "Category: PERIODIC OUTBOUND CONNECTIONS (BEACONING). A host connects out at regular intervals. Usually "
        "harmless: updaters, telemetry, cloud sync, well-known SaaS. Raise the score for uncategorised or "
        "proxy/anonymiser/remote-access destinations, rare destinations with regular tiny payloads, or unknown processes."),
    "auth_attack": (
        "Category: AUTHENTICATION ATTACK. Many failed logons, or a rule-matched resource attack. Usually harmless "
        "or already stopped: failures with ZERO successes, blocked/denied sources, service accounts with a stale "
        "password. Raise the score for a success after many failures, many distinct accounts from one source, or an "
        "allowed connection to the attacked resource."),
}
LENS_CAT = (("Excessive Firewall Denies", "fw_denies"), ("File Decode or Download", "endpoint_chain"),
            ("Mailto Ransomware", "endpoint_chain"), ("Process Launched from", "endpoint_chain"),
            ("Compromised Host", "endpoint_chain"), ("Endpoint Administration", "endpoint_chain"),
            ("C2 Beaconing", "beacon"), ("UC-01-1", "auth_attack"), ("UC-06-1", "auth_attack"),
            ("bruteforce", "auth_attack"), ("Kerberos", "auth_attack"))


def category_of(lens: str):
    for sub, cat in LENS_CAT:
        if sub.lower() in lens.lower():
            return cat
    return None


def build_c(prompt: str, cat: str, ev: list):
    """→ (prompt C, max_chars, len(logs C)) або None, якщо каркас не розпізнано."""
    if START not in prompt or END not in prompt or "Task: " not in prompt:
        return None
    pre, rest = prompt.split(START, 1)
    old_logs, tail = rest.split(END, 1)
    t = pre.index("Task: ")
    seg = pre[t + len("Task: "):]
    cut = seg.find("INTERNAL ASSET")
    assets = seg[cut:] if cut >= 0 else ""
    head = pre[:t]
    c_pre = head + "Task: " + CATEGORIES[cat] + "\n\n" + assets
    overhead = len(c_pre) + len(START) + len(END) + len(tail)
    max_chars = max(500, int((ab.CTX - ab.OUT_RESERVE) * ab.CHARS_PER_TOK) - overhead)
    logs = evidence_agg.render(ev, max_chars)
    return c_pre + START + logs + END + tail, max_chars, len(logs)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 30
    min_id = int(ab.arg("--min-id", 2185000))
    cases = [c for c in ab.pick(400, min_id) if category_of(c["lens"])]
    by = {}
    for c in cases:                                   # по колу з кожної категорії
        by.setdefault(category_of(c["lens"]), []).append(c)
    sel = []
    while len(sel) < n and any(by.values()):
        for k in list(by):
            if by[k] and len(sel) < n:
                sel.append(by[k].pop(0))
    if "--list" in sys.argv:
        for c in sel:
            print(c["ref"], category_of(c["lens"]), c["lens"][:45], c["label"])
        print(len(sel), "кандидатів")
        return
    cfg = json.load(open(f"{ab.BASE}/config.json"))
    res = []
    for c in sel:
        try:
            ev = ab.fetch_events(cfg, c["aql"], c["ref"])
        except Exception as e:
            print(c["ref"], "AQL помилка", type(e).__name__, flush=True)
            continue
        if not ev:
            print(c["ref"], "порожньо у вікні — пропуск", flush=True)
            continue
        cat = category_of(c["lens"])
        built = build_c(c["prompt"], cat, ev)
        if not built:
            print(c["ref"], "каркас промпту не розпізнано", flush=True)
            continue
        pc, mx, lc = built
        try:
            a, cc = ab.call(cfg, c["prompt"]), ab.call(cfg, pc)
        except Exception as e:
            print(c["ref"], "llm помилка", type(e).__name__, flush=True)
            continue
        res.append((c, cat, len(ev), a, cc))
        f = lambda r: f"{r['verdict']} {r['score']}"  # noqa: E731
        print(f"{c['ref']} {cat:14} ev={len(ev):4} budgetC={mx:5} logsC={lc:5} | A {f(a)} | C {f(cc)} | claude {c['label']}", flush=True)
    ok = [r for r in res if r[3]["score"] is not None and r[4]["score"] is not None]
    if not ok:
        return
    close = lambda x: x["score"] <= 0.6  # noqa: E731
    band = lambda x: 0.4 <= x["score"] <= 0.6  # noqa: E731
    print(f"\n=== {len(res)} випадків, розібрано {len(ok)} ===")
    print(f"A vs C: рішення збігається {sum(close(r[3]) == close(r[4]) for r in ok)}/{len(ok)}; сер. |Δscore| "
          f"{st.mean(abs(r[3]['score'] - r[4]['score']) for r in ok):.2f}; A→лишити {sum(not close(r[3]) for r in ok)}, "
          f"C→лишити {sum(not close(r[4]) for r in ok)}; смуга 0.4–0.6: A {sum(band(r[3]) for r in ok)}, C {sum(band(r[4]) for r in ok)}")
    for cat in sorted({r[1] for r in ok}):
        sub = [r for r in ok if r[1] == cat]
        print(f"  {cat:14} n={len(sub)} збіг {sum(close(r[3]) == close(r[4]) for r in sub)}/{len(sub)} "
              f"смуга A {sum(band(r[3]) for r in sub)} C {sum(band(r[4]) for r in sub)} "
              f"лишити A {sum(not close(r[3]) for r in sub)} C {sum(not close(r[4]) for r in sub)}")
    for name, i in (("A", 3), ("C", 4)):
        ag = [(r[i]["score"] > 0.6) == str(r[0]["label"]).startswith("review") for r in ok if r[0]["label"]]
        print(f"{name} vs мітка Claude (слабкий орієнтир): збіг {sum(ag)}/{len(ag)}")


if __name__ == "__main__":
    main()
