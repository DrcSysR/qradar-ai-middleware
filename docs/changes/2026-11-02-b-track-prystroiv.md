# 2026-11-02 — /track: трекінг пристроїв по QRadar + мапи Zabbix

## Задача

На вимогу: є список пристроїв (імена хостів / MAC / людина з реєстру), є карта розміщення
точок бездротового доступу — знайти останню реєстрацію пристрою на точці й показати
приблизне місце.

## Що є в даних (переміряно 02.11.2026)

- WLC Cisco 3504 (172.17.61.10) і старий Aruba (192.168.48.77) як log source у QRadar **не
  підключені**. Усе, що є про Wi-Fi, — RADIUS-події NPS XDC02/XDC05 (`IAS_SUCCESS - Accept
  Request`, IAS ODBC `\tN=value`): user (5/6), MAC клієнта (8), **Called-Station-ID (7) =
  `<AP>:<SSID>`** — ім'я точки є в Access-Request для обох SSID (`modern` 802.1X і `me_mac`
  MAB); в Accounting там системний MAC WLC, тож accounting не використовується. За добу видно
  98 точок Cisco (`CS_1xx_…`) і 15 Aruba (`ar_ware*`, склад). Дріт: NAS-Identifier (11) = ім'я
  свіча, Called-Station-ID = MAC порту.
- **RSSI/SNR у RADIUS немає** → відстань у метрах з QRadar порахувати неможливо. Рішення
  користувача: «точка + радіус» (умовний радіус покриття `track_ap_radius_m`, 20 м).
- Карта: Zabbix 7.0.32 (API `http://172.17.6.20/api_jsonrpc.php`, з mdlwr01 доступний),
  мапи «Розташування ТД Cisco»: **33 (2-й поверх) — 25 host-елементів `CS_1xx` з x,y і
  фоном-планом**; **35 (1-й поверх) — 24 image-елементи з підписом «ТД» без імен точок**;
  **34 (3-й поверх) — порожня**. Точки Aruba на мапах відсутні. Тобто позиція на плані зараз
  можлива лише для 25 точок 2-го поверху.
- Пошук по NPS за 72 год по 4 цілях (ILIKE по payload, зворотний слеш у ILIKE — літерал):
  4–30 с.

## Що зроблено

- `tracker.py` — реєстр «пристрій → людина» (JSON поза git), нормалізація імен/MAC, збирання
  одного AQL на всі цілі, розбір IAS-полів, агрегація last / last_wifi / last_wired / усі
  місця за вікно; індекс точок із Zabbix (`map.get` + `host.get` + `image.get`, Bearer-токен),
  кеш `cache/ap_map.json` + `cache/map_<id>.png` на `track_map_cache_hours`; підбір елемента
  мапи за host-ім'ям, інакше за підписом-префіксом (`CS_109` ↔ `CS_109_Eng03`).
- `app.py`: `POST /track {devices:[…], hours, refresh_map}` → JSON; `GET /track` — сторінка
  (textarea, вікно, таблиця «останній контакт / Wi-Fi / дріт», усі місця за вікно, план
  поверху з колом навколо точки); `GET /track/map/{id}` — фон мапи з кешу. Посилання з
  головної сторінки.
- `config_schema.py`: `zabbix_url`, `zabbix_api_token`, `track_zabbix_maps`,
  `track_registry_file`, `track_default_hours` 72, `track_max_hours` 720, `track_aql_limit`
  3000, `track_aql_timeout_seconds` 180, `track_ap_radius_m` 20, `track_map_cache_hours` 24,
  `track_map_scale_m_per_px` ({"33": 0.05}). `.gitignore`: `cache/`.
- Без токена Zabbix сторінка працює (точка/свіч/час показуються), місця на плані немає —
  з поясненням.

## Перевірка

Прогін `tracker.py` на mdlwr01 проти живого QRadar: INS04 → Wi-Fi `CS_109_Eng03:modern`
16:19, дріт `HPE-2540-74-R1202` 08:09, 2 MAC; сканер `1c-1a-1b-1a-81-d1` → `ar_ware05:me_mac`
(+ roaming по 5 точках складу); lgs53 → дріт `HPE-6100-38-R010101` 14:08, Wi-Fi
`CS_152_quality` 08:18. 180 подій за 4.3 с.

## Щоб запрацювало на проді (руками, не в git)

1. У Zabbix: користувач з правом читання мап (досить ролі User з доступом до host-групи
   «WiFi Cisco AP») → Administration → API tokens → токен. У `config.json`:
   `"zabbix_url": "http://172.17.6.20"`, `"zabbix_api_token": "…"`,
   `"track_zabbix_maps": [33, 34, 35]`.
2. `track_registry.json` у `/opt/qradar-middleware` (формат — у docstring `tracker.py`).
3. Мапи: на 1-му поверсі (35) замінити підписи «ТД» на імена точок або прив'язати елементи
   до хостів; 3-й поверх (34) наповнити; за бажанням — Aruba складу. Масштаб
   `track_map_scale_m_per_px` по кожній мапі (виміряти по плану), інакше коло умовне.

## Доповнення 2026-11-03 — лінза DHCP (коміти 493c033, 14abc28)

Тест на власних пристроях користувача: Chromebook (MAC відомий) — 48 реєстрацій на `CS_IT_02`
(SSID `modern`, обліковка `wifi.admin@modern.org`), точки на мапах немає. Телефон F6 —
**0 подій RADIUS за 7 діб**: SSID `me_mobile` — PSK, через NPS не ходить (у QRadar рядок
`me_mobile` не трапляється взагалі), MAC рандомізований.

Єдиний стабільний слід такого пристрою в QRadar — hostname у DHCP: `LinuxDHCP @ dhcp1`,
`DHCPACK on 172.17.107.241 to 82:9b:1d:23:f5:55 (F6) via eth0`. Тому в `tracker.py` додано
`build_dhcp_aql`/`assign_dhcp`: за `dhcp_host` з реєстру (або за відомим MAC) беремо
поточний MAC, IP і relay (= VLAN), а знайдені нові MAC ще раз проганяємо через RADIUS (на
випадок, якщо пристрій заходив і на `modern`/`me_mac`). У відповіді — `last_dhcp`,
`dhcp_macs` (скільки MAC змінилось за вікно); на сторінці — колонка «Останній DHCP» і
пояснення, чому нема точки.

**Межа методу:** для PSK-клієнтів точку доступу QRadar не бачить — її знає лише WLC. Щоб
закрити це «по радару», на WLC для WLAN `me_mobile` достатньо увімкнути **RADIUS accounting**
на NPS і поставити `Call Station ID Type = AP name:SSID` для accounting (зараз accounting
несе системний MAC контролера). Тоді `Accounting Request` понесе `<AP>:me_mobile` + MAC
клієнта, і лінза RADIUS запрацює й для телефонів (MAC за сесію постійний — DHCP дає його
через hostname). Альтернатива — живий SNMP/SSH до WLC (дає ще й RSSI), але це вже не QRadar.
