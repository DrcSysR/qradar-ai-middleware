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

## Доповнення 2026-11-03 — DHCP Palo Alto (коміт d5704c3) і інвентар Zabbix

- У QRadar подій DHCP від pa-vm немає взагалі (PaSeries за 7 діб без `dhcp`). Але сам pa-vm
  роздає адреси чотирьом сегментам, і таблицю оренд можна читати живцем (`show dhcp server
  lease interface all`, XML API `type=op`): `ethernet1/4.500` — гостьовий VLAN 500
  (172.18.48/21, 284 оренди, 249 з hostname-ами телефонів), `ethernet1/3.605` — VLAN точок
  доступу (172.17.65.x, hostname = ім'я точки `CS-…`), `ethernet1/2.10`, `ethernet1/2.12`.
  Це **стан, не історія**. Додано лінзу 3: `fetch_pa_dhcp`/`parse_pa_dhcp`/`assign_pa_dhcp`,
  колонка «DHCP Palo Alto (зараз)», знайдені MAC доганяються через RADIUS. Ключі
  `pa_api_host`, `pa_api_key`, `track_pa_dhcp_enabled`. ⚠️ Ключ має бути від окремого адміна з
  роллю «XML API: Operational Requests» (read-only): user-id-ключ QRadar на `type=op` дає 403, а
  superuser-ключ у `config.json` класти не можна. Телефон F6 і Chromebook користувача на PA
  DHCP не живуть (вони на `dhcp1`), тож для них ця лінза порожня за визначенням.
- Інвентар Zabbix (`inventory_mode=1`, ручний) заповнений лише у `CS_IT_01`: серійник,
  модель `AIR-AP2802I-E-K9`, `url_a`=172.17.65.117, GPS `50.743863, 25.394716`,
  `site_rack`="build 1 floor 2", місто/область. З 114 AP-хостів `location`=0, GPS=1, rack=1.
  Якби інвентар заповнили для всіх точок (`location_lat/lon` + `site_rack` як «будівля/поверх»),
  це дало б друге джерело місця без мап: координати → відстані між точками в метрах і
  посилання на карту; на плані поверху все одно потрібен елемент мапи.

## Доповнення 2026-11-03 — інвентар Zabbix і файл будівель (гео-прив'язка планів)

- `fetch_inventory` у лінзі Zabbix: `host.get withInventory + selectInventory` (`location_lat/lon`,
  `site_rack`, `location`, `site_city`, `model`, `serialno_a`, `url_a`) → `idx["inventory"]`; ключ
  `track_zabbix_inventory` (true). Читаються лише хости, де заповнено хоч щось із місця.
- Файл будівель `track_buildings_file` (`/opt/qradar-middleware/track_buildings.json`, поза git,
  будівель може бути кілька): для кожної — `name`, `inventory_match` (підрядки для site_rack),
  `corners` (GPS крайніх точок, ≥2, краще 3–4), `floors[]` = `{map, floor, px:{кут:[x,y]}}` —
  пікселі тих самих кутів на плані відповідної мапи Zabbix. `fit_georef` підбирає подібність
  (масштаб + поворот + зсув, МНК у комплексній формі) → `m_per_px` (замість ручного
  `track_map_scale_m_per_px`), `px_to_gps`/`gps_to_px`, похибка RMS у метрах.
- `with_location` тепер: елемент мапи (`source=map`, + GPS точки, якщо мапа прив'язана) →
  інвентарна точка з GPS на план тієї мапи, де збіглися будівля (inventory_match або GPS у
  контурі) і поверх (`floor` у site_rack/location) (`source=inventory`) → лише текст інвентарю +
  назва будівлі за контуром + посилання на Google Maps. Сторінка показує будівлю, інвентар, GPS,
  джерело позиції і джерело масштабу; статус — кількість хостів з інвентарем і прив'язаних мап.
- Кути будівлі на плані 2-го поверху (мапа 33, фон 3472×790): зовнішня стіна x 78…3368,
  y 127…655; верхній лівий блок починається з x=164 (нижня ліва частина виступає до x=78 від
  y≈263); сходова вежа зліва x 58…77, y 238…386; підпис «Корпус №2» праворуч за стіною.
  Контрольні точки для файлу: NE (3368,127), SE (3368,655), SW (78,655), NW (164,127).
- Перевірка на синтетиці (будівля 200×32 м, поворот 10°): масштаб і кут відновлено точно,
  round-trip px→GPS→px без похибки; точка з інвентарю `build 1 floor 2` лягає на мапу 33, точка
  `build 7 floor 1` — ні (поверх не збігся), точка без інвентарю й мапи — як раніше.
- Токен Zabbix (Bitwarden «API: Zabbix Midlware (admin)») зберігається на mdlwr01 окремим файлом
  `/opt/qradar-middleware/zabbix_api_token` (600 root:qmiddleware), `config.json` — лише `zabbix_url`
  і `track_zabbix_maps`; `tracker.zabbix_token()` бере ключ з конфігу, інакше з файлу
  (`zabbix_api_token_file`).
