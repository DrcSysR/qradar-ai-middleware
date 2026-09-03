"""Реєстр ключів config.json + валідація на старті.

Навіщо: у коді десятки викликів `APP_CONFIG.get("some_key", default)`. Одруківка в
ключі не падає — вона мовчки повертає дефолт, і поведінка змінюється непомітно
(саме так можна півдня шукати, чому не вмикається ескалація). Тут зібрані ВСІ відомі
ключі з типами й дефолтами; на старті конфіг звіряється з реєстром і в лог ідуть
попередження про невідомі ключі та невірні типи.

Свідомо БЕЗ pydantic-settings: на проді стоїть pydantic 2.12.5, а BaseSettings у v2
живе в окремому пакеті `pydantic-settings`, якого там немає. Тягнути новий пакет
заради валідації — відтворити рівно ту проблему з ручним встановленням залежностей,
яку ми й закриваємо. Тут лише stdlib.

Повертає ЗВИЧАЙНИЙ dict — усі наявні виклики `.get()` працюють без змін.

Реєстр перевіряється тестом `tests/smoke_test.py`: він вишукує в коді всі
`CONFIG.get("...")` і падає, якщо ключа немає тут. Тобто реєстр не роз'їдеться з кодом.
"""

import json
import logging
import os

NUM = (int, float)

# ключ: (тип, дефолт). Дефолт None = ключ обовʼязковий (без нього сервіс не працює).
SCHEMA = {
    # --- QRadar ---
    "qradar_url":                     (str,  None),
    "qradar_token":                   (str,  None),
    "aql_limit":                      (int,  1500),
    "reference_sets":                 (list, []),
    "refset_cache_ttl_seconds":       (NUM,  3600),
    "rules_map_cache_ttl_seconds":    (NUM,  3600),

    # --- вибір провайдера AI ---
    "ai_provider":                    (str,  "ollama"),
    "ai_fallback":                    (str,  ""),
    "ai_manual_provider":             (str,  ""),

    # --- моделі ---
    "fast_model":                     (str,  "qwen2.5-coder:7b"),
    "deep_model":                     (str,  "qwen2.5-coder:32b"),
    "vertex_fast":                    (str,  "gemini-1.5-flash"),
    "vertex_deep":                    (str,  "gemini-1.5-pro"),
    "vertex_project":                 (str,  ""),
    "vertex_location":                (str,  "us-central1"),

    # --- ендпоінти та таймаути ---
    "ollama_url":                     (str,  "http://127.0.0.1:11434"),
    "openai_base":                    (str,  ""),
    "openai_api_key":                 (str,  ""),
    "timeout_seconds":                (NUM,  600),
    "ollama_timeout_seconds":         (NUM,  600),
    "openai_timeout_seconds":         (NUM,  600),
    # Повтори на ТОМУ Ж провайдері перед тим, як віддавати офенс у fallback або лишати
    # його з AI_ERROR. Транзитні відмови tier-1 (зайняті слоти llm01) інакше одразу
    # оплачуються запитом у Vertex — саме так у серпні 2026 назбирався рахунок.
    "provider_retries":               (int,  1),
    "provider_retry_delay_seconds":   (NUM,  3),
    # Дедлайн полінгу Ariel. Пошук, що не встиг, скасовується → AQL_ERROR → офенс
    # лишається відкритим і буде переаналізований, а воркер не висить.
    "aql_poll_timeout_seconds":       (NUM,  180),

    # --- глибина вікна AQL (відраховується від часу офенсу, не від "now") ---
    # Скільки «передісторії» до старту офенсу підтягувати. Велике manual-вікно на гучних
    # лог-сорсах робить INOFFENSE скановищем на десятки ГБ — 168 ставити лише свідомо.
    "manual_window_hours":            (NUM,  24),
    "auto_window_hours":              (NUM,  4),
    # Стеля на розмах вікна AQL незалежно від віку офенсу: довгоживучий офенс інакше дає
    # INOFFENSE через півроку історії. Має бути >= escalate_window_hours, інакше тихо
    # зріже ескалацію.
    "max_aql_span_hours":             (NUM,  192),
    # Скільки AQL-«лінз» виконувати на композитному офенсі (кілька правил-учасників
    # одночасно). Кожна лінза = окремий пошук в Ariel, тож це стеля вартості.
    "max_aql_lenses_per_offense":     (int,  3),
    # Скільки офенсів поллер шле в мідлваре одночасно. Дорівнює кількості воркерів
    # gunicorn (3): більше лише створить чергу всередині сервісу.
    "poller_concurrency":             (int,  3),

    # --- каскадна тріаж (tier-2) ---
    "escalate_enabled":               (bool, False),
    "escalate_provider":              (str,  "vertex"),
    "escalate_model":                 (str,  ""),
    "escalate_threshold":             (NUM,  0.6),

    # Поріг РОЗБЛОКУВАННЯ (зняття IP із refset на FP-вердикті) — свідомо окремий і
    # нижчий за поріг авто-закриття 0.6. Закрити офенс і розблокувати файрвол мають
    # різну ціну помилки: 03.09.2026 спільний поріг давав 63 розблокування на добу
    # активних SSH-сканерів на вердикті `Suspicious_Keep_Watching` 0.4.
    "refset_cleanup_max_score":       (NUM,  0.3),

    # Зняття блоку вимагає вердикту ВАЖКОЇ моделі (tier-2). Якщо перегляду не було —
    # каскад вимкнений, ескалація впала, або tier-1 і так на esc_provider — блок
    # лишається. False повертає старе поводження (tier-1 вирішує сам).
    "refset_cleanup_requires_tier2":  (bool, True),
    "escalate_window_hours":          (NUM,  168),

    # --- загальне ---
    "debug_mode":                     (bool, False),
    "botnet_dry_run":                 (bool, False),

    # --- botnet_scan.py ---
    "botnet_scan_lookback_days":          (NUM,  7),
    "botnet_scan_max_adds_per_run":       (int,  50),
    "botnet_scan_review_stale_hours":     (NUM,  48),
    "botnet_scan_min_failed":             (int,  5),
    "botnet_scan_max_failed":             (int,  30),
    "botnet_scan_min_unique_users":       (int,  2),
    "botnet_scan_min_time_span_seconds":  (NUM,  0),
    "botnet_scan_aql_timeout_seconds":    (NUM,  600),
    "botnet_scan_internal_refsets":       (list, []),

    # --- falcon_pua_scan.py ---
    "falcon_pua_webhook_url":             (str,  ""),
    "falcon_pua_lookback_hours":          (NUM,  24),
    "falcon_pua_dedup_days":              (NUM,  30),
    "falcon_pua_aql_timeout_seconds":     (NUM,  600),
    "falcon_pua_max_aql_rows":            (int,  1000),
    "falcon_pua_max_report_items":        (int,  50),
    "falcon_pua_min_severity":            (NUM,  0),
    "falcon_pua_fp_path_regex":           (list, []),
    "falcon_pua_fp_filenames":            (list, []),
    "falcon_pua_fp_sha256":               (list, []),
    "falcon_pua_report_title":            (str,  ""),

    # --- cortex_xdr_scan.py ---
    "cortex_xdr_webhook_url":             (str,  ""),
    "cortex_xdr_lookback_hours":          (NUM,  24),
    "cortex_xdr_dedup_days":              (NUM,  30),
    "cortex_xdr_aql_timeout_seconds":     (NUM,  600),
    "cortex_xdr_max_aql_rows":            (int,  1000),
    "cortex_xdr_max_report_items":        (int,  50),
    "cortex_xdr_logsource_filter":        (str,  "Cortex XDR"),
    "cortex_xdr_min_severity":            (NUM,  3),
    "cortex_xdr_fp_alert_names":          (list, []),
    "cortex_xdr_fp_external_ids":         (list, []),
    "cortex_xdr_report_title":            (str,  ""),

    # --- cdn_allowlist_update.py ---
    "cdn_allowlist_providers":            (list, []),
    "cdn_allowlist_static_cidrs":         (list, []),
    "cdn_allowlist_target_set":           (str,  ""),
    "cdn_allowlist_botnet_set":           (str,  ""),
    "cdn_allowlist_http_timeout":         (NUM,  30),
    "cdn_allowlist_max_ips":              (int,  0),
    "cdn_allowlist_dry_run":              (bool, False),
}

# ключі, що починаються з "_", — документація всередині config.json, не налаштування
DOC_PREFIX = "_"


def validate(cfg: dict) -> tuple[list[str], list[str]]:
    """Повертає (errors, warnings). Нічого не логує і не змінює cfg."""
    errors, warnings = [], []

    for key, (typ, default) in SCHEMA.items():
        if key not in cfg:
            if default is None:
                errors.append(f"відсутній обовʼязковий ключ '{key}'")
            continue
        value = cfg[key]
        # bool — підклас int, тому перевіряємо його окремо й строго
        if typ is bool:
            if not isinstance(value, bool):
                errors.append(f"'{key}': очікується true/false, отримано {type(value).__name__}")
        elif typ is int and isinstance(value, bool):
            errors.append(f"'{key}': очікується число, отримано bool")
        elif not isinstance(value, typ):
            expected = typ.__name__ if not isinstance(typ, tuple) else "число"
            errors.append(f"'{key}': очікується {expected}, отримано {type(value).__name__}")

    for key in cfg:
        if not key.startswith(DOC_PREFIX) and key not in SCHEMA:
            warnings.append(f"невідомий ключ '{key}' — одруківка? (значення ігнорується)")

    return errors, warnings


def defaults() -> dict:
    """Довідкові дефолти зі схеми. НЕ підмішуються в конфіг автоматично — див. load()."""
    return {k: d for k, (_t, d) in SCHEMA.items() if d is not None}


def load(path: str, log=logging) -> dict:
    """Читає config.json, валідує за реєстром і пише проблеми в лог.

    СВІДОМО не підмішує дефолти зі SCHEMA у результат: у коді на кожному місці
    виклику вже є свій дефолт (`APP_CONFIG.get("deep_model", "qwen3.5:27b")`), і
    подекуди він відрізняється від значення в реєстрі. Підмішування тихо змінило б
    поведінку для ключів, яких немає в config.json. Тому повертаємо рівно те, що
    прочитали, — зміна поведінки нульова, а користь від валідації лишається.
    Значення зі SCHEMA слугують довідкою й основою для перевірки типів.

    Не кидає винятків: сервіс має піднятися навіть із кривим конфігом, інакше
    одна одруківка кладе тріаж повністю. Проблеми — гучно в лог.
    """
    raw = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            log.error(f"❌ config.json не розібрано ({path}): {e}. Працюємо на дефолтах.")
            raw = {}
    else:
        log.error(f"❌ config.json не знайдено ({path}). Працюємо на дефолтах.")

    errors, warnings = validate(raw)
    for w in warnings:
        log.warning(f"⚠️ config.json: {w}")
    for e in errors:
        log.error(f"❌ config.json: {e}")
    if not errors and not warnings:
        log.debug(f"config.json: {len(raw)} ключів, усі відомі й правильного типу.")

    return raw
