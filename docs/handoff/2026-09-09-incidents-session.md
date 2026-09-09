# Хендофф: інциденти 4–9 вересня 2026

**Стан на:** 09.09.2026, ~12:30 Київ · **Для чого:** продовжити сесію Claude Code з іншого пристрою
**Джерела:** QRadar (mdlwr01 172.17.61.225), PA pa-vm 172.17.64.101, nginx2 172.17.61.166, zimbra 172.17.61.120
**Репо мідлварі:** без змін коду за цей період (уся робота — PA / nginx2 / Wi-Fi / тріаж QRadar)

Усе нижче **виміряне**, не припущене. Два питання чекають на відповідь — позначені `❓`.
Пам'ять Claude із тими ж фактами лежить локально на `sysr` у
`~/.claude/projects/-home-sysr-github-qradar-ai-middleware/memory/` (файли
`pa_quic_silent_deny_slow_chrome.md`, `gap_nginx2_ssh_root_brute.md`, `lead_dns_large_queries.md`,
`lead_sp_nightly_egress_pavlo.md`, `pa_decrypts_google.md`) — з іншого пристрою її не видно, тому цей файл.

---

## Стан одним поглядом

| Нитка | Стан | Коротко |
|---|---|---|
| Google-підтвердження повільне з локалки | ✅ виправлено | тихий QUIC-дроп на PA → `drop` + ICMP unreachable; перевірено на твоєму egress |
| Bitwarden тупить у вкладці | 🟠 відкрито · на ноуті | однаково по дроту і Wi-Fi → мережа виключена; причина на ноуті |
| nginx2 SSH-брут | ✅ закрито | пароль вимкнено + fail2ban→PA `wan-block` + ignoreip; офенси закриті |
| Черга QRadar на `sergii.legerko` | ✅ 0 офенсів | 6 → 0 за 04–09.09; майже все — одна DNS-обхідна сім'я |
| 40 ГБ/ніч із sp.modern-expo.com | ✅ закрито | pavlo.fandych, dev-скрипт SUPPA 2.0, не ексфільтрація; віддано розробникам |
| Wi-Fi ноута флапає | 🟠 побічне | реконект кожні 90 с — таймер, не радіо; окремо від Bitwarden |
| conveniq beacon | 🔴 не перевірено | TTL блоку минув 26.08 — **жодного разу не перевірено**, чи відновився |

---

## 1. Повільна локалка — де зупинились

### 1.1 Google: причина знайдена і виправлена

Правило PA **`Prohibited Applications ALL`** (vsys1, локальний rulebase; `from LAN → to WAN`;
app-група «Prohibited Applications» = `quic`, bittorrent, bittorrent-sync, hamachi, mail.ru*, yandex-*,
vkontakte, odnoklassniki) блокувало QUIC (HTTP/3, UDP/443) **тихим дропом**. Chrome і телефони до Google,
Facebook, Apple і до Fastly (де сидить Bitwarden) спочатку йдуть по QUIC → чекали таймаут хендшейку →
лише потім TCP. Масштаб за добу: **1 295 хостів, 338 757 дропів** (топ: Instagram/Facebook Kyiv edge, Apple, Google).

- Перша спроба `reset-client` **не допомогла**: RST — лише TCP; UDP далі дропався тихо (120/120 свіжих подій `policy-deny`).
- Робоче: **`action=drop` + `Send ICMP Unreachable`**. Закомічено. Блок QUIC зберігається (свідомий контроль трафіку).
- QUIC для «клієнтів поза локалкою» (VPN-Lutsk 172.20.x, Lublin) **ще не виключено**: VPN-тунелі приземляються в зону LAN
  (`tunnel.16/17/22/23/24/108/200/201/300/2611` усі в LAN), тож `from=LAN` їх не рятує — VPN-Lutsk 30 хостів/737 дропів,
  Lublin 367 хостів/113 767 дропів за добу. Запропоновано allow-правило вище: `allow · app=quic · from=LAN · source=<VPN/віддалені пули> · to=WAN`.
  **Рішення потрібне:** які підмережі вважати «поза локалкою» (172.20.0.0/16 точно; Lublin 192.168.16–20.x?).

Вимір з LAN (`curl` з HTTP/3 з 172.17.64.241, **той самий egress що й у тебе** — `srcPostNAT 82.207.23.25 / ethernet1/1.7`, WAN-UT):

| Тест | Час | Результат |
|---|---:|---|
| QUIC-only → www.google.com | 0.21 с | exit 7 — відмова (ICMP дійшов), не таймаут |
| QUIC-only → accounts.google.com | 0.10 с | відмова |
| QUIC-only → vault.bitwarden.eu | 0.16 с | відмова |
| QUIC + фолбек → www.google.com | 0.31 с | → HTTP/2, 200 |
| QUIC + фолбек → vault.bitwarden.eu | 0.20 с | → HTTP/2, 200 |
| чистий TCP (базова лінія) | 0.22 с | штрафу за фолбек нема |

QoS виключено: жодне QoS-правило не класує LAN→WAN користувацький трафік; WAN-UT cap 500 Мбіт/с, живе ~175 кбіт/с.
Вирішальний інструмент — `curl --http3-only`; звичайний curl QUIC не використовує і дроп **не бачить** (тому перші тести були «швидкі»).

> ❓ **Питання 1.** Google-підтвердження після фіксу — швидке? Хочу закрити явно.

### 1.2 Bitwarden: мережа виключена, причина на ноуті

Підтверджено користувачем: **«та ж картина» по дроту (.226) і по Wi-Fi (.151)** — це один ноутбук. Це знімає мережу повністю:

- дріт: 0.9 % невдалих TCP-хендшейків (`Application=incomplete`), 0 % втрат до шлюзу і до 8.8.8.8 (0.28 мс / 21 мс);
- Bitwarden EU з того ж egress: `api/alive` 0.23 с, `identity` 0.16, `icons` 0.14, `vault` 0.20, WebSocket-upgrade 0.25 с (401 = шлях працює);
- PA: 0 deny/threat/reset до Bitwarden; URL-Filtering на нього = лише `alert` (`Allow Unrestricted - WAN`); розшифрування на .226 **немає**;
- ECH ні Fastly (Bitwarden), ні Google не публікують → Chrome його не пробує; WPAD/проксі не активні;
- з .151 до Bitwarden за добу лише 17 флоу — вкладка, що «тупить», майже не ходить у мережу.

З самого ноута в QRadar **нічого не летить** (нема Sysmon/Falcon/WinEvent з нього) → далі лише на машині.

**Чекліст на ноуті** (кожен крок відсікає половину варіантів):

1. **Інкогніто** (Ctrl+Shift+N — розширення вимкнені, чисте сховище) → vault.bitwarden.eu.
   Швидко → винен профіль Chrome (розширення, зокрема сам Bitwarden-extension у тій же вкладці, або роздутий IndexedDB) → крок 4.
   Тупить так само → машина або сховище → кроки 2–3.
2. **Shift+Esc** у момент лагу: CPU/пам'ять вкладки vault і процесу GPU. Вкладка 100 % = клієнтське розшифрування/рендер;
   GPU 100 % = вимкнути апаратне прискорення (`chrome://settings/system`).
3. **Той самий акаунт на іншому пристрої** (телефон / інший ПК). Лагає теж → розмір сховища / KDF
   (Bitwarden → Settings → Security → Keys: Argon2id з високою пам'яттю робить кожен unlock важким).
4. **Очистити site data для vault.bitwarden.eu** (`chrome://settings/content/all`) + тимчасово вимкнути Bitwarden-розширення → перелогінитись.
5. `chrome://settings/security` → **«Використовувати безпечний DNS» — вимкнути** (з ноута бачив DoH-спроби на 8.8.8.8 в обхід корп. DNS; не головна причина, зайва змінна).

> ❓ **Питання 2.** Результат кроку 1 (інкогніто) — швидко чи так само?

---

## 2. nginx2 — закрито як хост і як інцидент

172.17.61.166, openSUSE Leap 15.6, інтернет-фейсинг. Розподілений SSH-брут під `root`, потім під
`admin`/`postgres`/`ubuntu`; успіху ззовні жодного. Блокувати IP вручну було марно (джерела ротувались щодня).
Офенси #1300391 (по акаунту root) і #1333835 (по хосту) — один інцидент у двох проєкціях.

**Зроблено 08.09:**
- sshd: `PermitRootLogin prohibit-password`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`;
  бекап `/etc/ssh/sshd_config.bak.20260908-1136`; `sshd -t` → `systemctl reload sshd`; свіжий вхід по ключу перевірено.
  Обидва парольні акаунти (root, user) уже були на ключах — нікого не замкнуло.
- fail2ban 0.11.2 (як на zimbra): `jail.d/nginx2-ssh.conf` → `[sshd]`, `backend=systemd`, maxretry 4, findtime 3600,
  bantime 86400, `action=paloalto`; `action.d/paloalto.conf` → `push-ip.sh 172.17.64.101 <ip> <bantime> wan-block`;
  ключ `/etc/fail2ban/pa-api.key` (0600, скопійовано з zimbra пайпом, у транскрипт не потрапляв). firewalld вимкнений → лише PA-push, без локального iptables.
- 09.09: `ignoreip = 127.0.0.1/8 ::1 172.17.61.0/24 172.17.64.0/24 188.163.216.0/24` (серверний VLAN, IT VLAN —
  залочений Bitwarden-SSH-агент плодить root-фейли, — наш публічний егрес).

**Перевірено за ніч 08→09.09:** 20 PA-push OK / 0 збоїв; 0 успішних парольних входів; 3 321 спроба бруту (боти не зникають,
але не можуть увійти); обидва офенси затихли рівно в момент фіксу (11:13 / 11:39 08.09) і закриті 09.09 як мітигований TP.

SSH-аліас: **`ssh nginx2.modern.org`** (= 172.17.61.166). Плейн `nginx2` дивиться на публічний 188.163.216.105 і таймаутить на VPN.

---

## 3. Черга QRadar: 6 → 0

За 04–09.09 закрито 11 офенсів, що ескалювались на `sergii.legerko`. Майже всі — **одна доброякісна DNS-обхідна сім'я**
(клієнти на публічні/операторські резолвери повз корпоративний DNS):

| Цільовий «DNS» | Хто це (RDAP/PTR) | Джерела | Вердикт |
|---|---|---|---|
| `100.100.100.100` | AliDNS (Alibaba) | Люблін 192.168.16–19.x | WPS Office (збіг із master.ref) |
| `193.47.158.254/.255` | cache1/cache2.play.pl — ISP Play (P4) | Люблін | офіс на ISP-DNS; **повторюється щодня** (04, 07, 09.09) |
| `216.40.47.90` | ns1.systemdns.com (Tucows) | Люблін + LAN_OF | bpq 106–223 = не тунель (tier-1 llm01 хибно 0.9) |
| `80.255.64.23` | Vodafone UA (UMC-KIEV) | LAN_WIFI телефони | операторський DNS |
| `8.8.8.8` | Google Public DNS | Люблін, LAN_SRV, Default | PA частину сам ріже (Session Denied / ICMP drop) |
| `172.15.160.0` | AT&T (US), без PTR | корп. 172.17.x | лише PA-флоу без імен; дормант з 02.09; **reopen + endpoint-pivot, якщо прокинеться з bpq 400+** |

Окремо: #1331288 (mag6 «admin поза IT VLAN») — конгломерат акаунта `admin`: провалений зовнішній брут на nginx2 +
доброякісна активність адміна (pubkey-SSH з DMZ 188.163.216.98 на sp 35.205.227.94; логони на 172.17.102.104 і 192.168.50.86;
вхід у MikroTik Krymne 10.10.8.1 з 82.207.23.25 — підтверджено наш). Закрито; 3 брут-IP додано в `ME-PA-Suspicious-IP-Addresses`.

**Структурний хвіст, що генерує тріаж «з нічого»:** Люблінський сайт (192.168.16–20.x) треба перецілити на корпоративний
резолвер. Альтернатива — whitelist резолверів у рефсеті `UC05-DNS Servers` — осліпить весь UC-05, тому не робилось без слова ISO.

---

## 4. 40 ГБ/ніч із sp.modern-expo.com — закрито

sp = 35.205.227.94 (GCP, bitrix-project-23416). Тягне **MODERN\pavlo.fandych** (розробник), хост `DVL48.modern.org`
через VPN-Lutsk 172.20.23.119, процесом `C:\Users\pavlo.fandych\AppData\Local\Programs\Python\Python313\python.exe`
(запуск з Git bash / VS Code+Pylance / PyCharm 2026.1, каталоги `D:\prjct\SUPPA 2.0\MCP 20\`, `D:\prjct\Odin1c\`). Лише HTTPS 443.
**28 ГБ у ніч 07→08.09, 23:00–05:00** (пік 10.4 ГБ о 00:00). У 7-денному вікні QRadar лише ця ніч велика — «щоночі» даними не підтверджено.
Легітимна dev-робота по проєкту SUPPA 2.0 (= sp). Питання прод-даних на ноуті через VPN — віддано розробникам, без security-дій.

Метод (перевикористовуваний): PaSeries `SUM("Bytes Received")` по sourceip до dst → топ → `DATEFORMAT` по днях/годинах →
username з PA User-ID → процес із Sysmon EventID 3 (`Image`/`User` у полі Message).

---

## 5. Побічні знахідки з розбору

- **Wi-Fi ноута реконектиться метрономом кожні 90 с.** DHCPDISCOVER (MAC `a0:b3:39:b9:43:9e`, Intel) о 09:27:01, 28:30, 31:30,
  33:01, 34:31, 36:02, 37:31, 40:31, 42:02, 43:32 (пари по 3–4 с = ретрай); о 09:34:40 на мить перескочив на мобільний SSID
  (VLAN 104, 172.17.107.143). Фіксована періодичність = **таймер, не радіо**: Intel «Roaming Aggressiveness = Highest»
  (пінг-понг між двома AP з рівним сигналом) або power-save драйвера. 802.1X не винен: 16 NPS-grant, 0 deny.
  Кожен флап убиває всі TCP-сесії → client-RST 15 % на Wi-Fi vs 4 % на дроті (той самий ноут).
  *Фікс на ноуті:* Roaming Aggressiveness → Low/Medium, power-save off, оновити драйвер Intel.
  WLC (172.17.65.4, Cisco 3504) у QRadar **не логує** — deauth-причини лише на самому WLC (потрібен `bw unlock`).
- **802.1X по Wi-Fi ходить під спільним акаунтом `wifi.admin`** (NPS-grant на xdc02), не під AD-логіном користувача.
- **У VLAN 20 два шлюзи:** DHCP видає 172.17.64.1 (MAC `1c:34:da:ed:83:00` = Mellanox SVI, не VRRP-vMAC), статичні хости (.241)
  ходять через 172.17.64.5. Не збій, але тестовий хост і DHCP-клієнт можуть мати різний перший хоп — перевіряти перед довірою до «паритету шляху».
- **PA розшифровує Google** (Forward Proxy Decryption на `*.1e100.net`) для частини хостів (бачив на .241; на .226 нема).
  Був хибним слідом у цій справі; як факт — Google під розшифруванням ламає pinning, кандидат на виключення.
- **LAN_WIFI client-RST 39 % vs дріт 10–14 %** — виглядає системно, але сконфаундено телефонами. Тримати як «глянути», не діяти лише на цьому.
- Виправлення: «auth-фейли .151 до srv05/srvdbapp02» — це **Windows Filtering Platform blocked-connection audits**, не автентифікація.

---

## 6. Рішення власника (не тріаж)

| Що | Стан | Що потрібно |
|---|---|---|
| **conveniq.net beacon** (Conference-box-1, 172.18.53.78) | 🔴 не перевірено | інтерим-блок PA `no-lan` DAG ставився 19.08 з 7-денним TTL → минув ~26.08. Ймовірно beacon відновився ~2 тижні тому. Перевірити тег на PA і активність; перецілити агента на api.conveniq.net |
| **Zimbra** (172.17.61.120) | 🔴 вразливий | досі `8.8.11_GA_3737 (2018-12-07)` після підтвердженого pre-auth RCE 07.08 (217.69.9.174 — тиша). fail2ban→PA живий (recidive 988 банів). Патч/міграція — рішення власника сервісу |
| **Люблінський DNS** | 🟠 генерує FP щодня | перецілити клієнти сайту на корпоративний резолвер; whitelist у рефсеті — лише як свідоме послаблення UC-05 |
| **Спільні акаунти** | 🟠 governance | `admin` (робстанції + DC іншого сайту + MikroTik + SSH), `wifi.admin` (802.1X), `master.ref`, `o79834782` — вічно тригерять outside-VLAN/brute правила |
| **QUIC для VPN/віддалених** | 🟠 рішення | які пули вважати «поза локалкою» для allow-правила (див. 1.1) |
| **Edge fleet BitTorrent** (172.18) | 🟠 політичне | неавторизований P2P на продакшн-edge; IOC-мітка беззмістовна (swarm), у промпті вже FIRST CHECK |

---

## 7. Шпаргалка

```bash
# Чи PA ще стопить QUIC тихо / чи фікс тримається (з LAN-хоста з curl+HTTP/3, напр. 172.17.64.241):
curl --http3-only -so /dev/null --max-time 15 -w "%{time_total}s\n" https://www.google.com/    # ~0.1–0.2 с = ICMP працює; секунди = тихий дроп
curl --http3      -so /dev/null --max-time 20 -w "%{time_total}s h%{http_version}\n" https://vault.bitwarden.eu/

# nginx2
ssh nginx2.modern.org 'fail2ban-client status sshd; journalctl -t f2b-paloalto --since "24 hours ago" --no-pager | tail'
```

```sql
-- QRadar: хто впирається в QUIC-дроп
SELECT destinationip, COUNT(*) FROM events
 WHERE LOGSOURCENAME(logsourceid) ILIKE '%PaSeries%' AND QIDNAME(qid) ILIKE 'Session Denied%'
   AND "Application" ILIKE 'quic%' AND sourceip='<host>' GROUP BY destinationip LAST 24 HOURS

-- QRadar: дріт-vs-Wi-Fi підпис втрат одного хоста = частка "Application"='incomplete' серед Traffic End
-- (SYN пішов, хендшейк не завершився) + SessionEndReason у payload: tcp-fin здорово, aged-out губить, tcp-rst-from-client клієнт рве
```

Факти для API/скриптів:
- PA XML API читає конфіг ключем з `/etc/fail2ban/pa-api.key` (на zimbra і nginx2). Xpath — з **подвійними** лапками `[@name="vsys1"]`:
  у bash-одинарних `\x27` **не** стає апострофом і PA віддає `code=7` (об'єкт не знайдено). Panorama pre/post-rulebase порожні, правила локальні.
- QRadar рефсет bulk_load: `POST /api/reference_data/sets/bulk_load/{name}` (name **після** bulk_load; `/sets/{name}/bulk_load` → 404).
- Не робити повнотекстовий `UTF8(payload) ILIKE '%mac%'` по **всіх** подіях за добу — неіндексовано, вбито на 200 с. Скоупити по `LOGSOURCENAME` (DHCP/WLC). `python3 -u`, щоб часткові результати не пропали.
- ICMP-unreachable у PA не має лічильника з назвою «unreach»; емітовані unreachable-и видно як `appid_ident_by_icmp`. Довіряти `curl --http3-only`, не лічильнику.
- `show jobs all` через API віддає застарілі записи — не годиться для «коли був коміт».

---

## 8. ДОПОВНЕННЯ 09.09 ~13:00 — справжня причина ранкових «тормозів»: канал

Користувач уточнив: повільно було **08:00–10:00**, причина — навантаження на інтернет-канал. Перевірено по PaSeries (вікно START/STOP, Київ = UTC+3):

**Крива (весь інтернет-трафік):** 08:00 — 353 Мбіт/с → **плато 450–530 Мбіт/с 08:20–09:50**, пік 713 о 09:00; UP 30–65. Плато = стеля лінка.

**Лінк:** `srcPostNAT` у вибірці → **UT 82.207.23.25 / ethernet1/1.7 несе 94 % усіх інтернет-байтів офісу** (LAN_OF/WIFI/GU/IT/SRV/DCs/VPN-Lutsk — 85–100 % через UT). KS 188.163.216.98 ≈ 0 % (адмін/DMZ, простоює). QoS-профіль WAN-UT `egress-max 500` = плато → **UT ≈ 500 Мбіт/с, забитий**. Підтвердити контрактну швидкість UT.

**Не щоранку:** 09.09 (Patch Tuesday був 08.09) — 435 ГБ / сер. 484 / пік 713 Мбіт/с; 08.09 — 177 ГБ / 196 / 260; 04.09 — 201 ГБ / 223 / 264. Норма ранку ≈ 200–260 (половина UT). 09.09 — **×2.2**.

**Хто з'їв (2 години):**
| Призначення | Хто | Обсяг | Деталі |
|---|---|---:|---|
| `193.57.46.213/.231` | **A-Systems Sp. z o.o. (PL, 1-IX)** | **107.5 ГБ** | 394 хости / 350 юзерів, 12 959 сесій, 100 % HTTP:80 chunked (мед. 1 МБ, p90 16 МБ), ~0.27 ГБ/хост; серед хостів і conveniq-edge Windows-бокси 172.18.5x → **Windows Update з CDN-ноди**. Ім'я хоста з логів не дістати (`URL=` порожній, DNS логує лише запити) — підтвердити на ПК: `Get-DeliveryOptimizationLog \| ? Message -match '193\.57\.46'` |
| `199.232.214.172/.210.172` | **officecdn.microsoft.com** (Fastly) | 49.5 ГБ | `ms-update`, 107 юзерів у вибірці |
| `34.104.35.123` | **edgedl.me.gvt1.com** (Chrome) | 7.3 ГБ | |
| `109.61.38.38` | G-Core CDN, `ms-update` | 5.3 ГБ | |
| Telegram / FB+Google через UT-кеші 195.5.51.x | | 8 + 13 ГБ | норма |

≈ **170 ГБ апдейтів за 2 години ≈ +190 Мбіт/с** поверх базових ~250 → за стелю 500. **Хога нема** — десятки ПК по 2.1–2.9 ГБ кожен (один і той же апдейт).

Одиночні: `172.18.52.233` — GUEST VLAN 500, MAC `a4:b0:39:87:7d:78` (OUI Shenzhen iComm, IoT/TV-box), одна QUIC-сесія **11.5 ГБ** з Google — гостьовий пристрій, не наш. `security.video` (192.168.50.67) → `194.44.54.18` (BiT, UA) `unknown-tcp` 4.5 ГБ / 17 сесій — схоже на CCTV/NVR-синк; занотовано.

**Обидві причини справжні:** тихий QUIC-дроп — постійний податок на кожен Chrome-конект (виправлено), а гостра повільність 08–10 — ця сатурація.

**Фікси (рішення власника):**
1. **Delivery Optimization у LAN/Group-режимі** (GPO/Intune `DODownloadMode=2`, `DOGroupId`) або **Microsoft Connected Cache** on-prem — апдейт перетинає канал один раз; Office CDN теж поважає DO. Знімає ~150 ГБ хвилі.
2. **Розкласти в часі**: WU/Office active hours + deferral rings, щоб не всі о 08:00.
3. **PA QoS на LAN-боці** (ethernet1/2 уже має QoS-групу V20 / профіль LAN-20 egress-max 2000): клас `ms-update` + update-CDN низько з cap (~150 Мбіт/с), гарантія інтерактивному. Сьогодні жодне QoS-правило не класує LAN→WAN користувацький трафік.
4. **Задіяти простоюючий KS-лінк** (PBR/ECMP для bulk/update) або апгрейд UT.
