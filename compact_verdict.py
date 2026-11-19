"""Компактна відповідь локальної моделі (tier-1, llm01) і розшифрування для аналітика.

Навіщо: на llm01 (P620, 3 слоти на 8 потоків) генерація — ~60% часу запиту (≈52 токени при 3–7 ток/с), і більшість
токенів — пояснення на 15 слів. Модель віддає ЛИШЕ код рішення; людиночитний текст для нотатки в QRadar будує мідлвар
із самих подій (детерміновано, без генерації).

Формат відповіді моделі (один рядок, ≈15–20 токенів):
    {"score": 0.1, "verdict": "Benign_Thread_Injection"}
    {"score": 0.4, "verdict": "Unusual_Thread_Injection", "mitigated": true}     # mitigated — лише коли true
Тільки для провайдера `openai` (локальна модель). Tier-2 (Vertex) і ручний режим лишаються з повним форматом.
Рядки-константи спільні для app.py і tools/compact_ab.py, щоб тест перевіряв саме той текст, що йде в прод.
"""
import re

KEYS_FULL = "'score', 'verdict', 'explanation', and optionally 'mitigated'"
KEYS_COMPACT = "'score' and 'verdict' (add 'mitigated' ONLY when it is true)"

RULE3_FULL = ("3. 'explanation' MUST BE EXTREMELY CONCISE. Strictly 1 short sentence, maximum 15 words. "
              "Do not write long paragraphs.\n")
RULE3_COMPACT = ("3. Do NOT write any explanation or any other key: the middleware builds the human-readable "
                 "text itself. Output exactly one line like {\"score\": 0.1, \"verdict\": \"<EXACT VERDICT>\"}.\n")

# Поля подій, що не несуть суті для людини в короткій довідці
_SKIP = {"lens", "starttime", "endtime", "time"}
_HOST = ("hostname", "host", "host_name", "logsourcename", "src_host")
_COUNT = ("events", "count", "eventcount")


def to_compact(prompt: str) -> str:
    """Перетворює повний промпт у компактний (для офлайн-тесту на збережених промптах)."""
    return prompt.replace(KEYS_FULL, KEYS_COMPACT).replace(RULE3_FULL, RULE3_COMPACT)


def _short(v, n: int = 48) -> str:
    s = re.sub(r"\s+", " ", str(v)).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def decode(verdict: str, score: float, mitigated: bool, events, max_chars: int = 320) -> str:
    """Короткий текст для нотатки «Reason:». Лише факти з подій + код рішення моделі."""
    rows = [e for e in (events or []) if isinstance(e, dict)]
    head = f"Local model: {verdict} (score {score})"
    if mitigated:
        head += ", mitigated"
    if not rows:
        return head + ". No events in evidence."
    hosts, total = set(), 0
    for e in rows:
        low = {str(k).lower(): v for k, v in e.items()}
        for h in _HOST:
            if low.get(h):
                hosts.add(str(low[h]))
        for c in _COUNT:
            try:
                total += int(float(low.get(c)))
                break
            except (TypeError, ValueError):
                continue
    facts = f"{len(rows)} evidence row(s)" + (f", {total} events" if total else "") + (f", {len(hosts)} host(s)" if hosts else "")
    tops = []
    for e in rows[:2]:
        parts = [f"{k}={_short(v)}" for k, v in e.items()
                 if str(k).lower() not in _SKIP and str(k).lower() not in _HOST + _COUNT
                 and v not in (None, "", "null")][:4]
        if parts:
            tops.append("; ".join(parts))
    text = f"{head}. Evidence: {facts}" + (f". Top: {' | '.join(tops)}" if tops else "")
    return text if len(text) <= max_chars else text[: max_chars - 1] + "…"
