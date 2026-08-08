#!/usr/bin/env python3
"""Смоук-тест: перевіряє те, що ламається найчастіше і найтихіше.

Запуск (нічого встановлювати не треба, лише stdlib, QRadar не потрібен):

    python3 tests/smoke_test.py

Що саме ловимо — усе це реальні режими відмови цього проєкту:

1. Одруківка в назві .md у prompts.json → `get_dynamic_prompt` мовчки віддає
   DEFAULT_PROMPT_TEXT, і юзкейс аналізується generic-промптом. У логах — тиша.
2. Відсутній .aql → офенс падає в AQL_ERROR і висить відкритим.
3. Невідомий плейсхолдер у .aql (напр. {offence_id}) → `.format()` кидає KeyError
   ДО try/except у fetch_data_from_qradar, тобто 500 на весь запит.
4. Ключ конфіга, якого немає в config_schema.SCHEMA → валідація його не покриває,
   і одруківка в config.json лишається невидимою.
5. Синтаксична помилка в будь-якому модулі → сервіс не підніметься після autoupdate.

Код виходу: 0 — усе гаразд (warnings допускаються), 1 — є помилки.
"""

import ast
import json
import os
import py_compile
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPTS_JSON = os.path.join(BASE, "prompts.json")
PROMPTS_DIR = os.path.join(BASE, "prompts")
QUERIES_DIR = os.path.join(BASE, "queries")
PROD_CONFIG = "/opt/qradar-middleware/config.json"

# рівно те, що підставляє app.py у fetch_data_from_qradar
ALLOWED_PLACEHOLDERS = {"offense_id", "time_depth", "limit", "source_ip", "username"}
# як prompts_loader._resolve_config трактує 5-й елемент
TRUTHY_FLAGS = {"close_on_empty", "true", "1", "yes"}
META_KEYS = {"_COMMENT", "_DOCS"}
CONFIG_OBJECTS = {"APP_CONFIG", "CONFIG", "config", "cfg"}

errors: list[str] = []
warnings: list[str] = []


def fail(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


def entry_files(entry):
    """(md, aql, refset, flag) з елемента prompts.json — за логікою _resolve_config."""
    if isinstance(entry, str):
        return entry, None, None, None
    if isinstance(entry, list) and entry:
        md = entry[0] if isinstance(entry[0], str) else None
        aql = entry[2].strip() if len(entry) > 2 and isinstance(entry[2], str) and entry[2].strip() else None
        refset = entry[3].strip() if len(entry) > 3 and isinstance(entry[3], str) and entry[3].strip() else None
        flag = str(entry[4]).strip() if len(entry) > 4 else None
        return md, aql, refset, flag
    return None, None, None, None


def check_prompts_mapping():
    if not os.path.exists(PROMPTS_JSON):
        fail("prompts.json не знайдено")
        return set(), set()
    try:
        with open(PROMPTS_JSON, encoding="utf-8") as f:
            mapping = json.load(f)
    except Exception as e:
        fail(f"prompts.json не розбирається: {e}")
        return set(), set()

    used_md, used_aql = set(), set()
    rules = {k: v for k, v in mapping.items() if k not in META_KEYS}

    if "Default" not in rules:
        fail("prompts.json: немає запису 'Default' — офенси без збігу лишаться без промпту")

    for key, entry in rules.items():
        if not isinstance(entry, (str, list)):
            fail(f"prompts.json['{key}']: очікується рядок або список, отримано {type(entry).__name__}")
            continue
        md, aql, _refset, flag = entry_files(entry)

        if not md:
            fail(f"prompts.json['{key}']: перший елемент має бути назвою .md файлу")
        else:
            used_md.add(md)
            if not os.path.exists(os.path.join(PROMPTS_DIR, md)):
                fail(f"prompts.json['{key}']: немає prompts/{md} — юзкейс мовчки піде на generic-промпт")

        if aql:
            used_aql.add(aql)
            if not os.path.exists(os.path.join(QUERIES_DIR, aql)):
                fail(f"prompts.json['{key}']: немає queries/{aql} — офенси впадуть в AQL_ERROR")

        if flag is not None and flag.lower() not in TRUTHY_FLAGS:
            warn(f"prompts.json['{key}']: 5-й елемент '{flag}' не розпізнається як прапорець "
                 f"(очікується одне з {sorted(TRUTHY_FLAGS)}) — close_on_empty лишиться вимкненим")

    return used_md, used_aql


def check_queries(used_aql):
    if not os.path.isdir(QUERIES_DIR):
        fail("немає теки queries/")
        return
    dummy = {k: "X" for k in ALLOWED_PLACEHOLDERS}
    for name in sorted(os.listdir(QUERIES_DIR)):
        if not name.endswith(".aql"):
            continue
        path = os.path.join(QUERIES_DIR, name)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        try:
            text.format(**dummy)
        except KeyError as e:
            fail(f"queries/{name}: невідомий плейсхолдер {e} — .format() впаде з KeyError "
                 f"(дозволені: {sorted(ALLOWED_PLACEHOLDERS)})")
        except (IndexError, ValueError) as e:
            fail(f"queries/{name}: непарна фігурна дужка або кривий формат ({e}); "
                 f"літеральні дужки треба подвоювати")
        if name not in used_aql and name != "default.aql":
            warn(f"queries/{name} не згадується в prompts.json (сирота?)")


def check_orphan_prompts(used_md):
    if not os.path.isdir(PROMPTS_DIR):
        fail("немає теки prompts/")
        return
    for name in sorted(os.listdir(PROMPTS_DIR)):
        if name.endswith(".md") and name not in used_md:
            warn(f"prompts/{name} не згадується в prompts.json (сирота?)")


def collect_subscript_keys():
    """Ключі, що читаються ЧЕРЕЗ ІНДЕКС (APP_CONFIG["x"]), а не .get().

    Такий доступ падає з KeyError, якщо ключа немає в config.json — і падає на рівні
    модуля, тобто сервіс просто не підніметься. Отже такий ключ фактично обовʼязковий
    і має бути позначений обовʼязковим у SCHEMA (дефолт None), інакше реєстр обіцяє,
    що ключ можна не вказувати, а насправді його відсутність кладе прод.
    """
    keys = set()
    for name in sorted(os.listdir(BASE)):
        if not name.endswith(".py"):
            continue
        try:
            tree = ast.parse(open(os.path.join(BASE, name), encoding="utf-8").read(), filename=name)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                    and node.value.id in CONFIG_OBJECTS and isinstance(node.slice, ast.Constant)
                    and isinstance(node.slice.value, str)):
                keys.add(node.slice.value)
    return keys


def collect_config_keys():
    """Ключі конфіга, що фактично використовуються в коді: літеральні
    CONFIG.get("..."), CONFIG["..."] і ключі словників DEFAULTS у сканерах."""
    keys = set()
    for name in sorted(os.listdir(BASE)):
        if not name.endswith(".py"):
            continue
        path = os.path.join(BASE, name)
        try:
            tree = ast.parse(open(path, encoding="utf-8").read(), filename=name)
        except SyntaxError:
            continue  # про синтаксис повідомить check_compiles
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get" and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in CONFIG_OBJECTS and node.args
                    and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                keys.add(node.args[0].value)
            if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                    and node.value.id in CONFIG_OBJECTS and isinstance(node.slice, ast.Constant)
                    and isinstance(node.slice.value, str)):
                keys.add(node.slice.value)
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "DEFAULTS" and isinstance(node.value, ast.Dict):
                        for k in node.value.keys:
                            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                keys.add(k.value)
    return keys


def check_config_registry():
    sys.path.insert(0, BASE)
    try:
        import config_schema
    except Exception as e:
        fail(f"не імпортується config_schema: {e}")
        return
    used = collect_config_keys()
    missing = sorted(used - set(config_schema.SCHEMA))
    if missing:
        fail("config_schema.SCHEMA не описує ключі, які використовує код: " + ", ".join(missing))
    unused = sorted(set(config_schema.SCHEMA) - used)
    if unused:
        warn("у SCHEMA є ключі, яких код не читає (застаріли?): " + ", ".join(unused))

    # Ключ через індекс = сервіс не підніметься без нього, тож у SCHEMA він має бути
    # обовʼязковим. Інакше реєстр каже "необовʼязковий", а видалення ключа кладе прод.
    for key in sorted(collect_subscript_keys()):
        entry = config_schema.SCHEMA.get(key)
        if entry and entry[1] is not None:
            fail(f"'{key}' читається через індекс CONFIG['{key}'] (KeyError без нього, "
                 f"сервіс не стартує), але в SCHEMA позначений необовʼязковим — "
                 f"або зробіть його required (дефолт None), або читайте через .get()")

    if os.path.exists(PROD_CONFIG) and os.access(PROD_CONFIG, os.R_OK):
        try:
            with open(PROD_CONFIG, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            fail(f"{PROD_CONFIG} не розбирається: {e}")
            return
        errs, warns = config_schema.validate(cfg)
        for e in errs:
            fail(f"config.json: {e}")
        for w in warns:
            warn(f"config.json: {w}")


def check_compiles():
    with tempfile.TemporaryDirectory() as tmp:
        for name in sorted(os.listdir(BASE)):
            if not name.endswith(".py"):
                continue
            try:
                py_compile.compile(os.path.join(BASE, name),
                                   cfile=os.path.join(tmp, name + "c"), doraise=True)
            except py_compile.PyCompileError as e:
                fail(f"{name}: синтаксична помилка — {e.msg.strip()}")


def main():
    used_md, used_aql = check_prompts_mapping()
    check_queries(used_aql)
    check_orphan_prompts(used_md)
    check_config_registry()
    check_compiles()

    for w in warnings:
        print(f"  WARN  {w}")
    for e in errors:
        print(f"  FAIL  {e}")

    print(f"\nпідсумок: помилок {len(errors)}, попереджень {len(warnings)}")
    if errors:
        print("СМОУК-ТЕСТ НЕ ПРОЙДЕНО")
        return 1
    print("СМОУК-ТЕСТ ПРОЙДЕНО")
    return 0


if __name__ == "__main__":
    sys.exit(main())
