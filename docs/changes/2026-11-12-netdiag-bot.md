# 2026-11-12 — netdiag: Google Chat-бот діагностики підключення пристрою (Wi-Fi / дріт)

**Статус:** код і інфраструктура розгорнуті на mdlwr01 + nginx2; лишились два ручні кроки в консолях
Google (див. «Відкрито»).
**Прод:** mdlwr01 — `netdiag-collector.service` (знімки раз на хвилину), `netdiag-bot.service`
(`https://172.17.61.225:5010`); публікація — `https://netdiag.modern-expo.ua/chat` (nginx2).

## Навіщо

Helpdesk/NOC на скаргу «не працює мережа» має швидко відповісти: де пристрій (точка Wi-Fi чи
свіч/порт), чи він взагалі авторизувався і чому ні. Раніше це ручний обхід WLC, свічів і NPS-логів.
Алгоритм від користувача: IP → MAC (DHCP/ARP) → де підключений → розгалуження: Wi-Fi — усе з
контролера + історія 10–15 хв; дріт — свіч, порт, стан авторизації і причина відмови.

## Що переміряно (12.11.2026)

- **WLC Cisco 3504** (172.17.65.4, AireOS 8.10.196.0, точки в local mode): SNMP v2c працює
  лише для спільнот, прив'язаних до IP (була лише Zabbix 172.17.6.21 і LibreNMS 172.17.6.173).
  mdlwr01 має ногу у VLAN 605 (172.17.65.9) → створено **окрему RO-спільноту для
  172.17.65.9/32** (`config snmp community create/ipaddr/accessmode ro/mode enable`, `save config`);
  значення — у Bitwarden «SNMP: WLC 3504 community netdiag (mdlwr01)» і в config.json.
  Повна таблиця клієнтів (~740) + 114 AP + радіо — ~1 с SNMP.
  Корисні колонки: `bsnMobileStationEntry` (.2 IP, .3 user, .4 AP MAC, .5 slot, .7 SSID, .9 status,
  .10 reason, .23 **policy-manager state** RUN/8021X_REQD/DHCP_REQD, .29 VLAN, .30 protocol),
  `bsnMobileStationStatsEntry` (.1 RSSI, .26 SNR, .2/.3 байти), `cldcClientEntry` (.15 uptime,
  .17 rate, .44 device type), AP — `bsnAPName/Location/Model/IpAddress`, радіо —
  канал/завантаження/кількість клієнтів.
- **Ядро MLNX01/02** (172.17.6.1/.2, Cumulus 4.3): ARP усіх користувацьких VLAN (~2900 записів на
  кожному; HW-STACK тримає лише 172.17.6/64). Інтерфейси `vlanN` / `vlanN-v0` (VRR).
- **Свічі**: 95→108 SNMP-хостів у групах Zabbix `Switches`/`NetHw`; спільноти різні, частина в
  макросах шаблонів — розв'язуються з Zabbix API на льоту (кеш `cache/netdiag_switches.json`, 600).
  **6.117 (HPE-2540-117, сюди ввімкнений WLC) у Zabbix вимкнений, але живий** — тому вимкнені хости
  не відкидаємо. LLDP-MIB віддають лише HP/Aruba; Huawei HW-STACK і Cumulus по наших
  спільнотах — ні. На HW-STACK натомість ifAlias аплінків = ім'я сусіднього свіча
  («HPE-2530-86-R010102:28»). Aruba CX 6100 / Ubiquiti / частина HP 2530 SNMP не відповідають.
- **NPS у QRadar**: події 6272/6273 (`Success/Failure Audit: Network Policy Server granted/denied
  access to a user`, лог-сорси XDC0x) містять Calling Station Identifier (MAC), Called Station
  (AP:SSID), NAS, політику, тип автентифікації, **Reason Code і текст причини**. Пошук по MAC за
  60 хв — ~2 с.

## Що зроблено

- `snmp_v2c.py` — мінімальний SNMP v2c (GET/GETBULK-walk) на stdlib: на mdlwr01 немає ні net-snmp,
  ні pysnmp; нова залежність не потрібна. Адаптивний розмір пачки (Huawei не встигає на 40).
- `netdiag.py` — логіка:
  1. IP → MAC: знімок ARP ядра (свіжіший 3 хв), інакше живий обхід; запасний шлях — DHCPACK у
     QRadar (`track_dhcp_logsource`, 24 год).
  2. MAC є на WLC → **Wi-Fi**: живий GET за індексом MAC (точка, SSID, VLAN, діапазон/канал,
     RSSI/SNR, rate, стан політик, uptime, тип пристрою, завантаження радіо) + **історія з
     знімків** за `netdiag_history_minutes` (15): ланцюжок точок (роумінг), RSSI/SNR
     мін/сер/макс, перепідключення (скинутий uptime), пропущені знімки. Якщо зараз на WLC
     немає, але був у вікні — «відвалився о HH:MM від точки X».
  3. Інакше **дріт**: паралельний GET `dot1dTpFdbPort.<mac>` (+ `dot1qTpFdbPort.<vlan>.<mac>`) на
     всіх свічах (~3–5 с), для кожного хіта — bridge-порт → ifIndex, ifName/ifAlias, up/down,
     швидкість, помилки, PVID, час останньої зміни, IEEE8021-PAE (стан 802.1X), LLDP-сусід.
     **Крайовий порт** = хіт, за яким немає іншого свіча-хіта (LLDP-сусід або ifAlias з його
     іменем); при кількох — спершу свічі з LLDP, ядро в кінці. Сусід за портом: Ubiquiti →
     «за PoE-свічем Ubiquiti X» без деталей (так попросив користувач), IP-телефон, WLC,
     невідомий свіч.
  4. NPS (QRadar): дозволено/відмовлено за 60 хв, остання подія, топ причин відмов.
  5. Евристики висновків: RSSI ≤ −75/−67, SNR < 20, канал ≥ 60 %, 2.4 ГГц, ≥3 роумінги,
     перепідключення; порт down, помилки, < 1 Гбіт/с, 802.1X unauthorized, VLAN 500.
- `netdiag_collector.py` + `netdiag-collector.service` — цикл 60 с: WLC (клієнти, AP, радіо) +
  ARP ядра → `netdiag.db` (окрема SQLite, не ai_state.db), чистка > 30 хв (ARP — 6 год).
- `netdiag_bot.py` + `netdiag-bot.service` — FastAPI/uvicorn на `172.17.61.225:5010` з TLS
  (самопідписаний серт `netdiag_tls/`, nginx2 його пінить). На кожен запит: TCP-джерело лише
  nginx2 (172.17.61.166), OIDC-токен Google Chat (aud = URL ендпоінта, email
  `chat@system.gserviceaccount.com`), користувач — `@modern-expo.com` і член **noc@**
  (Cloud Identity `checkTransitiveMembership`, SA `netdiag-bot@me-network-diagnistics`) або
  `netdiag_allowed_users`; ліміт 6 запитів/хв; IP лише з `netdiag_allowed_networks`. Відповідь
  синхронна (≤ 26 с бюджету; Chat чекає 30 с).
- GCP: окремий проєкт **`me-network-diagnistics`** («ME Network Diagnistics», № 862146426046, організація
  modern-expo.com, без білінгу) — один проєкт = одна конфігурація Chat app, а Chat-застосунок бота
  тривоги вже живе в `me-s3-backup-project-79601`. Увімкнено Chat API і Cloud Identity API, SA
  `netdiag-bot` + ключ (`/opt/qradar-middleware/netdiag_sa.json`, 640 root:qmiddleware). Спершу
  все це було зроблено в alARM (`causal-shell-436205-a8`) — там уже є інший застосунок (Firebase),
  тому перенесено: SA видалено, Chat/Cloud Identity API вимкнено (до 12.11 вони там не були
  ввімкнені — перевірено аудит-логом), alARM у вихідному стані.
- DNS: `netdiag.modern-expo.ua A 188.163.216.105` (зона `modern-expo-ua`, проєкт `me-cloud-dns-zones`).
- nginx2: `vhosts.d/netdiag.conf` (копія в репо `deploy/nginx2/netdiag.conf`), Let's Encrypt
  `netdiag.modern-expo.ua`; публічний лише `POST /chat`, `/healthz` — LAN, решта 404.
- `autoupdate.sh`: після успішного рестарту — `systemctl try-restart netdiag-collector netdiag-bot`.

## Вигляд відповіді (того ж дня, за відгуком користувача)

Відповідь — картка Google Chat (`cardsV2`, `netdiag.render_card`), а не текст одним абзацом:
заголовок (IP · MAC · Wi-Fi/кабель), розділи з іконками — Wi-Fi / Сигнал і стан / Історія /
Висновок / Авторизація NPS (для кабелю — Кабельне підключення / Стан порту). Значення
забарвлені за рівнем: зелений норма, помаранчевий гранично, червоний погано — RSSI (> −67 /
−67…−75 / < −75 dBm), SNR (≥ 25 / 15…25 / < 15 dB), завантаження каналу (< 40 / < 60 / ≥ 60 %),
швидкість порту (< 1 Гбіт/с), помилки, VLAN 500, 802.1X, стан RUN, відмови NPS. Історія Wi-Fi —
ряд RSSI похвилинно (кожне значення своїм кольором, ✕ — клієнта не було на WLC). Усі рядки з
обладнання екрануються (`html.escape`) перед вставкою в HTML картки.

## Palo Alto: зняти wan-block / дати tmp-inet (того ж дня, на запит користувача)

`netdiag_pa.py` — дії на **pa-vm** (лише VM-300 172.17.64.101; pa440 — ні, рішення 07.08) через User-ID XML
API (`type=user-id`, uid-message):
- `розблокуй 1.2.3.4` — unregister тегів `netdiag_pa_unblock_tags` (wan-block) з **публічного** IP; якщо
  unregister не вдався — register з `timeout=1` (як у формі helpdesk, тег спливає за секунду);
- `інтернет 172.17.40.25 4г` / `8 год` / `2д` — register `tmp-inet` з `timeout` у секундах, `persistent=1`,
  лише IP з `netdiag_allowed_networks`, 1 год … 720 год (30 діб — і стеля PAN-OS 2592000 с);
- під діагностичною карткою внутрішнього IP — кнопки tmp-inet 1 год / 4 год / 8 год / 1 день / 7 днів.
Кожна дія — через картку підтвердження (кнопки «Підтвердити»/«Скасувати»; підтвердження живе 10 хв,
після натискання картка замінюється результатом — подвійне натискання неможливе). Клікер авторизується
наново (`netdiag_pa_group`, типово noc@), параметри кнопки валідуються як недовірений ввід. Аудит —
таблиця `pa_actions` у `netdiag.db` (ts, user, action, ip, tag, timeout_s, ok, detail) + журнал бота.

Ключ — **user-id-only** ключ `ibm.qradar` (BW «PaloAlto API Key», поле `pa-vm ibm.qradar (user-id only)`;
найменші права, що дозволяють тегування; admin-ключ боту не дається), у config.json
`netdiag_pa_uid_key`, передається заголовком X-PAN-KEY (не в query string). TLS до PA — повна перевірка
корпоративним CA MODERN-CA-G2 (`netdiag_tls/modern-ca-g2.pem`; серт PA має IP SAN 172.17.64.101).
Перевірено порожнім uid-message: 200 success. Показ поточних тегів IP потребує op-ключа
(`netdiag_pa_op_key`, порожній) — user-id ключ на op отримує 403; без нього картка пише «теги не читаються».
Спільний ключ із 9 custom actions QRadar: при його ротації треба оновити й `netdiag_pa_uid_key`.

## Кнопки і діалоги (того ж дня, на запит користувача)

`netdiag_ui.py`. На будь-яке повідомлення без IP/команди, «меню»/«help» і додавання бота — **картка-меню**
з кнопками, кожна відкриває діалог (`interaction: OPEN_DIALOG`):
- **Діагностика IP** → поле IP/MAC → картка діагностики окремим повідомленням;
- **Інтернет (tmp-inet)** → внутрішній IP + строк зі списку (1 год … 30 днів) або свій у годинах → тег на pa-vm;
- **Зняти wan-block** → публічний IP → unregister.
Під карткою діагностики — «Перевірити ще раз», «Інтернет…» (діалог з підставленим IP), «Меню». Діалог сам
є підтвердженням (людина бачить поля і тисне «Застосувати»); помилки вводу повертаються в той самий діалог
(`actionStatus INVALID_ARGUMENT`), він не закривається. Кнопки PA бачать лише члени `netdiag_pa_group`;
кожен submit авторизується і валідується заново.
**Таймаут діалогу:** на submit діалогу Google чекає лише ~8 с (о 16:15 nginx 499 на 8-й секунді), а діагностика з NPS —
5–10 с. Тому «Діагностувати» і «Перевірити ще раз» відповідають одразу («Діагностую…»), а картку бот надсилає окремим
повідомленням через Chat API (`spaces.messages.create`, SA `netdiag-bot` з scope `chat.bot` — автентифікація як застосунок).
Текстовий IP у чаті лишився синхронним (там 30 с).
**Один тред під меню:** усі результати (діагностика, tmp-inet, wan-block, «Перевірити ще раз») бот надсилає в тред
повідомлення, з кнопки якого почали, — тобто в тред картки-меню. Спершу було «окремий тред на дію», але на
телефоні купа тредів незручна (відгук користувача того ж дня). Кожна дія має ID `#xxxxxx`: у підзаголовку
картки, префіксом `[#id]` у кожному рядку `netdiag_bot.log` (start/done, thread=…) і в `pa_actions.detail` —
за ним картка в треді зіставляється з журналом. Відповідь на сам діалог Chat клав би в головний чат, тому
діалог закривається коротким статусом, а картка йде в тред через Chat API. Текстові команди (`розблокуй …`, `інтернет … 4г`) лишились —
через картку підтвердження.

## Відкрито (ручні кроки — лише в консолях Google)

1. ✅ зроблено 12.11 — **Google Chat API → Configuration** у проєкті `me-network-diagnistics`: назва/аватар, «Receive 1:1 messages» +
   «Join spaces», Connection = **HTTP endpoint URL** `https://netdiag.modern-expo.ua/chat`,
   Authentication audience = **HTTP endpoint URL**, Visibility = `noc@modern-expo.com`.
   НЕ вмикати «Build this Chat app as a Workspace add-on» (бот відповідає у форматі класичних
   подій `MESSAGE`).
2. ✅ зроблено 12.11 — **Admin console → Account → Admin roles → Groups Reader** → призначити
   `netdiag-bot@me-network-diagnistics.iam.gserviceaccount.com` (як для SA бота тривоги). До цього
   перевірка noc@ падає → відмова всім, крім `netdiag_allowed_users`.

## Межі

- **Мережі, які маршрутизує Palo Alto** (гостьовий VLAN 500 172.18.48.0/21, VLAN точок 605): ARP там
  на PA, не на MLNX, DHCP — теж PA. Wi-Fi-клієнтів цих мереж бот знаходить за IP у таблиці клієнтів
  WLC (знімок ≤ 10 хв; так знайдено 172.18.48.139 на CS_IT_02, 347 клієнтів `me_guest`). **Дротові**
  пристрої там (conveniq edge) — поки ні: потрібен read-only XML API ключ PA (`show arp`, DHCP-оренди)
  від окремого адміна з роллю лише Operational Requests — у Bitwarden такого немає (є лише
  user-id-ключ QRadar і superuser). Це перший крок запланованого функціоналу Palo Alto в боті.

- Ubiquiti, Aruba CX 6100, частина HP 2530 SNMP не віддають: пристрій за ними видно лише до
  останнього свіча з SNMP (бот так і пише).
- Історія Wi-Fi — лише з моменту старту колектора, крок 1 хв (короткі обриви < 1 хв видно як
  скинутий uptime, не як пропуск).
- PSK-клієнти (`me_mobile`) у NPS не потрапляють — для них «подій NPS немає» нормально.
- Zabbix API з mdlwr01 іде на `http://172.17.6.20` (так у `zabbix_url`) — токен по LAN без TLS;
  успадковано від /track.
