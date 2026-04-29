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


def _resolve_config(config) -> tuple[str, str | None, str]:
    """Розпарсити елемент мапінгу: рядок або список [filename, assignee, aql_file]."""
    filename = ""
    assignee = None
    aql_file = DEFAULT_AQL_FILE

    if isinstance(config, str):
        filename = config
    elif isinstance(config, list) and len(config) > 0:
        filename = config[0]
        if len(config) > 1 and isinstance(config[1], str) and config[1].strip():
            assignee = config[1].strip()
        if len(config) > 2 and isinstance(config[2], str) and config[2].strip():
            aql_file = config[2].strip()

    return filename, assignee, aql_file


def get_dynamic_prompt(rule_name: str, prompts_file: str, prompts_dir: str) -> tuple[str, str | None, str]:
    """Знайти у prompts.json першу секцію, ключ якої є substring назви офенсу.
    Повертає (prompt_text, assignee, aql_filename). Якщо нічого не знайдено — Default; якщо й Default немає — фолбек."""
    mapping = _load_mapping(prompts_file)
    if not mapping:
        return DEFAULT_PROMPT_TEXT, None, DEFAULT_AQL_FILE

    rule_lower = rule_name.lower()

    # 1. Точкові правила
    for key, config in mapping.items():
        if key in META_KEYS:
            continue
        if key.lower() in rule_lower:
            filename, assignee, aql_file = _resolve_config(config)
            filepath = os.path.join(prompts_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, "r", encoding="utf-8") as pf:
                    return pf.read(), assignee, aql_file
            return DEFAULT_PROMPT_TEXT, None, DEFAULT_AQL_FILE

    # 2. Default
    if "Default" in mapping:
        filename, _, aql_file = _resolve_config(mapping["Default"])
        filepath = os.path.join(prompts_dir, filename)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as pf:
                return pf.read(), None, aql_file

    return DEFAULT_PROMPT_TEXT, None, DEFAULT_AQL_FILE
