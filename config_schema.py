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

    # --- черга work_queue / worker.py (запис 2026-09-23) ---
    # Скільки офенсів воркер віддає в /process-one одночасно. Дорівнює кількості воркерів
    # gunicorn (3): більше лише створить чергу всередині сервісу (переміряно 2026-08-28).
    "worker_concurrency":             (int,  3),
    # Оренда на IN_PROGRESS: має бути більшою за timeout_seconds аналізу, інакше живий
    # офенс заберуть удруге. Воркер упав — після спливу рядок повертається в чергу сам.
    "worker_lease_seconds":           (NUM,  900),
    "worker_max_attempts":            (int,  3),
    "worker_batch_per_run":           (int,  0),      # 0 = дренаж до порожньої черги
    # Черга переставляє роботу, а не додає потужності: при припливі > дренажу росте хвіст
    # QUEUED. Sweep дропає його low-mag частину, старшу за TTL; high-mag не чіпає ніколи.
    "queue_sweep_low_mag_max":        (int,  3),
    "queue_sweep_ttl_days":           (NUM,  3),
    "queue_done_retention_days":      (NUM,  14),
    "queue_alert_depth":              (int,  1500),   # WARNING у worker.log при QUEUED ≥
    # /process-one віддав status "error" (AQL/AI впали) → рядок ERROR; поллер force-перекладе
    # його в QUEUED не раніше, ніж через стільки годин, якщо офенс досі OPEN у вікні.
    "queue_error_retry_hours":        (NUM,  6),
    # --- переоцінка довгоживучих офенсів (poller.py, фаза 2; запис 2026-11-02) ---
    # Поллер бачить лише офенси, СТВОРЕНІ за 48 год. Офенс, що живе тижнями й у який
    # QRadar щодня доливає події, випадає з вікна назавжди — аудит 02.11.2026 знайшов 22
    # OPEN mag-7 офенси з вересня–жовтня без жодного вердикту. Фаза 2 бере OPEN офенси
    # старші за вікно, з magnitude >= min_magnitude і свіжим last_updated_time, і кладе
    # їх у чергу з force (переоцінка PROCESSED) не частіше, ніж раз на interval_hours.
    # span_hours обрізає AQL до свіжого хвоста офенсу (інакше INOFFENSE за 45 діб не
    # завершується — та сама причина, що в tools/catchup.py). max_per_run обмежує
    # вартість рану (кожен кандидат = до одного API-виклику за нотатками).
    "poller_retriage_enabled":        (bool, True),
    "poller_retriage_min_magnitude":  (int,  6),
    "poller_retriage_interval_hours": (NUM,  24),
    "poller_retriage_span_hours":     (NUM,  24),
    "poller_retriage_max_per_run":    (int,  30),
    # Пріоритет пісочниці (/chat) над тріажем: на повідомлення app.py ставить hold на
    # chat_hold_seconds — воркер не бере нових офенсів, поточний дороблює; чат чекає
    # вільний слот llm01 до chat_wait_seconds; після відповіді hold ще chat_grace_seconds.
    "chat_hold_seconds":              (NUM,  120),
    "chat_grace_seconds":             (NUM,  45),
    "chat_wait_seconds":              (NUM,  120),

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

    # Порожній результат AQL юзкейсу без close_on_empty = «невідомо», а не «чисто».
    # Перед тим як ставити NO_EVENTS (і зникати з поля зору поллера назавжди), пробуємо
    # default.aql — сирі події офенсу без бенін-фільтрів. Замір 03.09.2026: так залипло
    # 133 відкритих офенси.
    "fallback_to_default_aql":        (bool, True),
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
    "cortex_xdr_lookback_hours":          (NUM,  25),
    "cortex_xdr_dedup_days":              (NUM,  30),
    "cortex_xdr_max_report_items":        (int,  50),
    "cortex_xdr_api_fqdn":                (str,  ""),
    "cortex_xdr_api_key_id":              (str,  ""),
    "cortex_xdr_api_key":                 (str,  ""),
    "cortex_xdr_api_security":            (str,  "advanced"),
    "cortex_xdr_console_url":             (str,  ""),
    "cortex_xdr_page_size":               (int,  100),
    "cortex_xdr_max_alerts":              (int,  1000),
    "cortex_xdr_api_timeout_seconds":     (NUM,  60),
    "cortex_xdr_skip_whitelisted":        (bool, True),
    "cortex_xdr_min_severity":            (NUM,  3),
    "cortex_xdr_fp_alert_names":          (list, []),
    "cortex_xdr_fp_external_ids":         (list, []),
    "cortex_xdr_report_title":            (str,  ""),

    # --- трекінг пристроїв /track (tracker.py; запис 2026-11-02) ---
    # Джерело місця — RADIUS-події NPS у QRadar (Called-Station-ID 'AP:SSID'); карта точок —
    # мапи Zabbix (map.get/host.get/image.get, токен API з правом читання мап). Реєстр
    # «пристрій → людина» — JSON поза git. Радіус = умовне покриття точки; масштаб
    # метри/піксель задається на кожну мапу окремо ({"33": 0.05}), без нього коло умовне.
    "zabbix_url":                         (str,  ""),
    "zabbix_api_token":                   (str,  ""),
    # Якщо zabbix_api_token порожній — токен читається з цього файлу (600 root:qmiddleware, поза git)
    "zabbix_api_token_file":              (str,  "/opt/qradar-middleware/zabbix_api_token"),
    "track_zabbix_maps":                  (list, []),
    "track_registry_file":                (str,  "/opt/qradar-middleware/track_registry.json"),
    "track_default_hours":                (NUM,  72),
    "track_max_hours":                    (NUM,  720),
    "track_aql_limit":                    (int,  3000),
    "track_aql_timeout_seconds":          (NUM,  180),
    "track_ap_radius_m":                  (NUM,  20),
    "track_map_cache_hours":              (NUM,  24),
    "track_map_scale_m_per_px":           (dict, {}),
    # Інвентар Zabbix (location_lat/lon, site_rack, location) — друге джерело місця точки без мапи
    "track_zabbix_inventory":             (bool, True),
    # Опис будівель: GPS крайніх точок + пікселі тих самих кутів на кожному плані поверху (мапі
    # Zabbix) → масштаб м/px і GPS для будь-якої точки плану; формат — у docstring tracker.py
    "track_buildings_file":               (str,  "/opt/qradar-middleware/track_buildings.json"),
    # Лог-сорс DHCP для другої лінзи (ISC dhcpd на dhcp1; 172.17.61.254 дублює ті самі події)
    "track_dhcp_logsource":               (str,  "LinuxDHCP @ dhcp1"),
    # Лінза 3: живі оренди DHCP-сервера pa-vm через XML API (type=op). Ключ — окремий адмін з
    # роллю «XML API: Operational Requests» (read-only), не superuser і не user-id-ключ QRadar.
    "pa_api_host":                        (str,  ""),
    "pa_api_key":                         (str,  ""),
    "track_pa_dhcp_enabled":              (bool, True),

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
