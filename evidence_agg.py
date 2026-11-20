"""Агрегація рядків доказів перед підрізанням під контекст локальної моделі (tier-1, llm01).

Навіщо: llm01 має ctx 8192, на події лишається `max(500, …)` символів, а `str(events)[:max_chars]`
різав repr списку на пів рядка — модель бачила 1–3 рядки, решту втрачала мовчки. Сирі рядки
(firewall-deny із RawPayload, повтори Sysmon) майже однакові між собою, тож тут вони згортаються:

  1. ключ групи = усі поля, КРІМ мінливих (час) і лічильників; однакові рядки зливаються;
  2. лічильник = сума `Events`/`Count`, а для сирих рядків — кількість злитих (`Events` додається);
  3. довгі текстові поля (RawPayload, шляхи) підрізаються до `MAX_FIELD` символів;
  4. рядки, що не влізли, НЕ ріжуться посеред — в кінець додається маркер `_omitted` із числом
     пропущених груп і подій, щоб модель знала, що бачить не все.

Формат виходу лишається Python-літералом списку словників (той самий, що й раніше), тому
`tools/dataset_label.py` і ai_dataset.py парсять збережені промпти без змін. Порядок груп — за першою
появою (як віддав AQL: зазвичай `ORDER BY starttime DESC`); сортувати за кількістю не можна —
рідкісний рядок і є тим, заради чого лінза існує, і сортування за спаданням віддало б його в обрізку.
"""
from __future__ import annotations

VOLATILE = {"time", "starttime", "endtime", "first_seen", "last_seen"}
# Сирий текст події: у ключ групи НЕ входить (містить мітки часу, тож робить кожен рядок унікальним),
# у групі лишається перший зразок, підрізаний до MAX_FIELD.
SAMPLE = {"rawpayload", "payload", "utf8(payload)"}
COUNT_KEYS = ("events", "count", "eventcount")
MAX_FIELD = 160
OMIT_KEY = "_omitted"


def _low(e: dict) -> dict:
    return {str(k).lower(): k for k in e}


def aggregate(events) -> list[dict]:
    """Згортає однакові рядки. Нерозпізнане (не dict) віддає як є на початок не чіпаючи."""
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []
    passthru: list = []
    for e in events or []:
        if not isinstance(e, dict):
            passthru.append(e)
            continue
        names = _low(e)
        count_key = next((names[c] for c in COUNT_KEYS if c in names), None)
        try:
            n = int(float(e[count_key])) if count_key is not None else 1
        except (TypeError, ValueError):
            n = 1
        key_items, samples = [], []
        for k, v in e.items():
            lk = str(k).lower()
            if lk in VOLATILE or k == count_key or v in (None, "", "null"):
                continue
            (samples if lk in SAMPLE else key_items).append((k, str(v)[:MAX_FIELD]))
        key = tuple(key_items)
        g = groups.get(key)
        if g is None:
            row = {k: v for k, v in key_items + samples}
            row["Events"] = n
            groups[key] = row
            order.append(key)
        else:
            g["Events"] += n
    return passthru + [groups[k] for k in order]


def _collapse(rows: list[dict], max_chars: int) -> list[dict]:
    """Стадія 2: поки не влазить — згортаємо поле з найбільшою кількістю різних значень
    (типово destinationip при розгортці з одного джерела): рядки, що відрізняються лише ним,
    зливаються в один із `<n> distinct (зразки…)`. Лічильники Events складаються."""
    done: set = set()
    while len(repr(rows)) > max_chars:
        fields: dict = {}
        for r in rows:
            for k, v in r.items():
                if k == "Events" or k in done or str(k).lower() in SAMPLE:
                    continue
                fields.setdefault(k, set()).add(str(v))
        cand = [(len(v), k) for k, v in fields.items() if len(v) > 1]
        if not cand:
            break
        _, field = max(cand)
        done.add(field)
        groups: dict = {}
        for r in rows:
            key = tuple((k, str(v)) for k, v in r.items() if k not in ("Events", field) and str(k).lower() not in SAMPLE)
            g = groups.get(key)
            if g is None:
                g = {k: v for k, v in r.items() if k != field}
                g["Events"] = 0
                g["_vals"] = []
                groups[key] = g
            g["Events"] += r.get("Events", 1)
            if r.get(field) is not None and r[field] not in g["_vals"]:
                g["_vals"].append(r[field])
        out = []
        for g in groups.values():
            vals = g.pop("_vals")
            g[field] = f"{len(vals)} distinct" + (f" ({', '.join(map(str, vals[:3]))}{', …' if len(vals) > 3 else ''})" if len(vals) > 1 else (f": {vals[0]}" if vals else ""))
            out.append(g)
        rows = out
    return rows


def render(events, max_chars: int) -> str:
    """repr згорнутого списку, що влазить у max_chars; хвіст — маркером, не обрізкою."""
    rows = aggregate(events)
    if len(repr(rows)) > max_chars:
        rows = _collapse(rows, max_chars)
    total = sum(r.get("Events", 1) for r in rows if isinstance(r, dict))
    text = repr(rows)
    if len(text) <= max_chars:
        return text
    kept: list = []
    used = 2  # дужки
    marker_room = 90
    for r in rows:
        cost = len(repr(r)) + 2
        if used + cost + marker_room > max_chars and kept:
            break
        kept.append(r)
        used += cost
    rest = rows[len(kept):]
    if rest:
        rest_events = sum(r.get("Events", 1) for r in rest if isinstance(r, dict))
        kept.append({OMIT_KEY: f"{len(rest)} more groups, {rest_events} of {total} events"})
    text = repr(kept)
    return text if len(text) <= max_chars else text[:max_chars]
