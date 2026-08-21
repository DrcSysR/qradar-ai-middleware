"""Спільний loader для prompts.json — використовується і app.py (резолв правил → промпт+AQL+assignee)
і poller.py (фільтр офенсів за назвами правил)."""
import json
import logging
import os

DEFAULT_PROMPT_TEXT = "Analyze logs for malicious activity."
DEFAULT_AQL_FILE = "default.aql"

# Ключі, які в prompts.json є метаданими, а не правилами
META_KEYS = {"_COMMENT", "_DOCS", "Default"}


def _load_mapping(prompts_file: str) -> dict:
    if not os.path.exists(prompts_file):
        return {}
    try:
        with open(prompts_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error reading prompts mapping {prompts_file}: {e}")
        return {}


def get_rule_keys(prompts_file: str) -> list[str]:
    """Повертає список substring-ключів правил (без Default, _COMMENT, _DOCS).
    Використовується поллером для фільтрації офенсів."""
    mapping = _load_mapping(prompts_file)
    return [k for k in mapping.keys() if k not in META_KEYS]


def _iter_match_texts(description, rule_names):
    """Тексти для матчингу в порядку пріоритету: спершу опис офенсу, потім назви
    правил-учасників. rule_names — фолбек для офенсів, чий опис QRadar згенерував
    з імені події (напр. 'Traffic End', 'incorrect password'), а не з імені UC-правила."""
    yield description or ""
    for rn in (rule_names or []):
        yield rn or ""


def _match_all_configs(mapping, description, rule_names=None):
    """Усі секції, чий ключ є substring опису офенсу АБО назви якогось правила-учасника,
    у порядку пріоритету (опис → правила), без дублів. Повертає [(key, config), ...]."""
    out = []
    seen = set()
    for text in _iter_match_texts(description, rule_names):
        tl = text.lower()
        if not tl:
            continue
        for key, config in mapping.items():
            if key in META_KEYS or key in seen:
                continue
            if key.lower() in tl:
                seen.add(key)
                out.append((key, config))
    return out


def _match_config(mapping, description, rule_names=None):
    """Перша секція (у порядку prompts.json), чий ключ є substring опису офенсу
    АБО назви правила-учасника. Повертає config або None. META_KEYS ігноруються.
    Делегує в _match_all_configs, щоб пріоритет тут і в get_matched_lenses не розійшовся."""
    matches = _match_all_configs(mapping, description, rule_names)
    return matches[0][1] if matches else None


def get_matched_lenses(description: str, prompts_file: str, rule_names: list | None = None) -> list[dict]:
    """Усі зматчені юзкейси («лінзи») для офенсу, у порядку пріоритету.

    Композитний офенс QRadar несе кілька правил одночасно (спостережений приклад:
    інжект у процес + зловживання sc.exe + C2-бікон + UC-07-1 на одному хості).
    Матчинг за одним ключем давав ОДНУ лінзу: виконувався тільки її AQL, а докази
    решти правил-учасників не потрапляли в запит узагалі — і в парі з close_on_empty
    офенс закривався як benign score 0.0, бо *своя* лінза була чиста. Тому app.py
    бере промпт/assignee/refset від першої лінзи, а події збирає з AQL усіх.

    Кожен елемент: {key, prompt_file, assignee, aql_file, refset_cleanup, close_on_empty}.
    Порожній список = жодного збігу (далі спрацьовує Default у get_dynamic_prompt)."""
    mapping = _load_mapping(prompts_file)
    if not mapping:
        return []
    lenses = []
    for key, config in _match_all_configs(mapping, description, rule_names):
        prompt_file, assignee, aql_file, refset_cleanup, close_on_empty = _resolve_config(config)
        lenses.append({
            "key": key,
            "prompt_file": prompt_file,
            "assignee": assignee,
            "aql_file": aql_file,
            "refset_cleanup": refset_cleanup,
            "close_on_empty": close_on_empty,
        })
    return lenses


def offense_matches(rule_keys, description, rule_names=None) -> bool:
    """True, якщо хоч один rule_key є substring опису офенсу або назви правила-учасника.
    Використовується поллером як фільтр 'чи слати офенс на AI-аналіз'."""
    keys_lower = [k.lower() for k in rule_keys]
    for text in _iter_match_texts(description, rule_names):
        tl = text.lower()
        if tl and any(k in tl for k in keys_lower):
            return True
    return False


def _resolve_config(config) -> tuple[str, str | None, str, str | None]:
    """Розпарсити елемент мапінгу: рядок або список
    [filename, assignee, aql_file, refset_cleanup, close_on_empty].
    refset_cleanup — назва reference set, з якого треба видалити entity IP при FP-вердикті
    (порожній рядок або відсутність — ніяких дій з refset).
    close_on_empty (5-й елемент, опційний) — якщо truthy ('close_on_empty'/'true'/'1'/'yes'),
    то коли AQL не повертає жодної події, офенс закривається як benign (score 0.0) замість SKIP.
    Призначене для monitoring-юзкейсів, де AQL сам відфільтровує benign і порожній результат = чисто."""
    filename = ""
    assignee = None
    aql_file = DEFAULT_AQL_FILE
    refset_cleanup = None
    close_on_empty = False

    if isinstance(config, str):
        filename = config
    elif isinstance(config, list) and len(config) > 0:
        filename = config[0]
        if len(config) > 1 and isinstance(config[1], str) and config[1].strip():
            assignee = config[1].strip()
        if len(config) > 2 and isinstance(config[2], str) and config[2].strip():
            aql_file = config[2].strip()
        if len(config) > 3 and isinstance(config[3], str) and config[3].strip():
            refset_cleanup = config[3].strip()
        if len(config) > 4 and str(config[4]).strip().lower() in ("close_on_empty", "true", "1", "yes"):
            close_on_empty = True

    return filename, assignee, aql_file, refset_cleanup, close_on_empty


def get_dynamic_prompt(rule_name: str, prompts_file: str, prompts_dir: str, rule_names: list | None = None) -> tuple[str, str | None, str, str | None, bool]:
    """Знайти у prompts.json першу секцію, ключ якої є substring опису офенсу
    АБО назви будь-якого з правил-учасників (rule_names). Збіг за описом має пріоритет;
    rule_names — фолбек для офенсів, чий опис QRadar згенерував з імені події, а не з імені UC.
    Повертає (prompt_text, assignee, aql_filename, refset_cleanup, close_on_empty).
    close_on_empty=True лише для зматченого юзкейсу з 5-м елементом-прапорцем; Default/фолбек — False."""
    mapping = _load_mapping(prompts_file)
    if not mapping:
        return DEFAULT_PROMPT_TEXT, None, DEFAULT_AQL_FILE, None, False

    # 1. Точкові правила: спершу опис офенсу, потім назви правил-учасників
    config = _match_config(mapping, rule_name, rule_names)
    if config is not None:
        filename, assignee, aql_file, refset_cleanup, close_on_empty = _resolve_config(config)
        filepath = os.path.join(prompts_dir, filename)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as pf:
                return pf.read(), assignee, aql_file, refset_cleanup, close_on_empty
        return DEFAULT_PROMPT_TEXT, None, DEFAULT_AQL_FILE, None, False

    # 2. Default
    if "Default" in mapping:
        filename, _, aql_file, _, _ = _resolve_config(mapping["Default"])
        filepath = os.path.join(prompts_dir, filename)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as pf:
                return pf.read(), None, aql_file, None, False

    return DEFAULT_PROMPT_TEXT, None, DEFAULT_AQL_FILE, None, False
