# qradar-ai-middleware — поточний стан

**Актуально на:** 2026-08-27 · **Керує:** скіл `qradar-soc` + `CLAUDE.md` репо · **Прод:** так

## 1. Призначення і межі

Сервіс автоматичного тріажу офенсів QRadar через LLM. Читає офенс із QRadar REST,
підбирає під нього промпт і AQL-запит, віддає агрегований результат моделі, отримує
JSON-вердикт (`score` / `verdict` / `explanation` / `mitigated`) і на його підставі
**закриває офенс, призначає аналітику або знімає IP із блок-листа Palo Alto**.

Не входить: правила кореляції в самому QRadar (їх редагують у веб-консолі),
онбординг лог-сорсів (релей `api-gw`, окремий скіл), операції з firewall поза
reference set'ами.

## 2. Компоненти, хости, мережа

| Компонент | Хост / IP | Роль |
|---|---|---|
| `qradar-middleware.service` | mdlwr01 (172.17.61.225) | FastAPI+gunicorn, 3 воркери uvicorn, `0.0.0.0:5000` |
| `qradar-poller.timer/.service` | mdlwr01 | oneshot кожні 10 хв (`OnUnitActiveSec=10min`) |
| QRadar (event collector, API) | 172.17.61.184 | джерело офенсів і подій, Ariel-пошуки |
| llm01 (`openai` провайдер) | on-prem llama.cpp `/v1` | tier-1 модель авто-тріажу |
| Vertex AI | GCP | tier-2 ескалація + manual-режим |
| Palo Alto pa-vm | 172.17.64.101 | цільовий firewall блок-листів (через QRadar reference sets) |

Прод-дерево — `/opt/qradar-middleware` (той самий git-репо, `autoupdate.sh` робить
`git pull` на місці).

## 3. Як це працює (механізми)

```
QRadar offenses API ──► poller.py (кожні 10 хв, вікно 48 год, ліміт 100/ран)
                          │ фільтр: OPEN + опис/назва правила є ключем у prompts.json
                          │ skip: status=PROCESSED у ai_state.db або вже є нотатка "AI Analysis"
                          ▼
              POST 127.0.0.1:5000/universal-analysis {offense_id, is_manual:false}
                          │
   app.py: offense details ─► prompts.json: УСІ зматчені лінзи (опис + правила-учасники)
                          │  промпт/assignee/refset — від лінзи №1, події — з AQL усіх (cap 3)
                          ├─ AQL: POST /ariel/searches → полінг (дедлайн) → results → DELETE
                          ├─ порожній результат + close_on_empty → авто-закриття score 0.0
                          ├─ порожній без прапорця → NO_EVENTS, офенс лишається відкритим
                          ├─ AQL не виконався → AQL_ERROR, офенс лишається відкритим
                          ▼
             tier-1 (llm01) ──score > escalate_threshold──► tier-2 (Vertex, вікно 168 год)
                          ▼
     вердикт → нотатка в офенс + одне з: close / assign / залишити відкритим
                          └─ FP + налаштований refset → DELETE IP із блок-листа
```

Матчинг юзкейсу — **substring опису офенсу**, з фолбеком на **назви правил-учасників**
(бо QRadar часто називає офенс іменем події, напр. «Traffic End», а не іменем UC).

Вердикт → дія (авто-режим):

| Умова | Дія |
|---|---|
| `mitigated: true` | закрити, блок лишити |
| `score ≤ 0.6`, не mitigated | закрити; якщо для правила заданий refset і entity=IP → **зняти IP із блок-листа** |
| `score > 0.6` + assignee | лишити відкритим, призначити |
| `is_manual: true` | ніколи не закриває автоматично |

Побічні джоби (cron на mdlwr01): `falcon_pua_scan.py` (09:00, дайджест Falcon PUP у
Google Chat), `cdn_allowlist_update.py` (06:30, рефсет CDN-allowlist ~22 тис. IP),
`botnet_scan.py` (systemd timer, кожні 4 год, review+hunt блок-листа),
`cortex_xdr_scan.py` (**свідомо вимкнений** до жовтня 2026 — фід мертвий з 2026-08-04).

## 4. Ключові файли й скрипти

| Шлях | Що робить |
|---|---|
| `app.py` | FastAPI: `POST /universal-analysis`, `GET /` (HTML-форма ручного запуску) |
| `poller.py` | standalone-поллер під systemd timer |
| `prompts.json` | мапа: ключ опису → `[prompt.md, assignee, query.aql, refset_cleanup?, close_on_empty?]` |
| `prompts/*.md`, `queries/*.aql` | інструкція моделі та AQL під кожен юзкейс |
| `prompts_loader.py` | резолв мапінгу + фолбек на `Default` |
| `config_schema.py` | реєстр ключів `config.json` з типами й дефолтами, валідація на старті |
| `tests/smoke_test.py` | смоук: одруківки в `prompts.json`, відсутні `.aql`, невідомі плейсхолдери, невідомі ключі конфігу, синтаксис модулів |
| `tools/aql_runner.py`, `tools/ai_state_stats.py` | ручна діагностика |
| `autoupdate.sh`, `deploy.sh` | деплой: pip → смоук-гейт → рестарт → health → rollback |

Стан — `ai_state.db` (SQLite): таблиці `offenses`, `botnet_scan`,
`falcon_pua_reported`, `cortex_xdr_reported`.

## 5. Доступ і секрети

- SSH: `ssh mdlwr01` (ключ через SSH-агент Bitwarden; при потребі `ProxyJump nginx2`).
- `config.json` — **гітіґнорений**, містить QRadar SEC-токен, webhook Google Chat,
  параметри Vertex. Ключ Vertex — окремий JSON поруч, теж не в git.
- Пароль/токени шукати в Bitwarden (запис по назві сервісу), не в репо.
- `.gitignore` ігнорує `*.json`, крім `prompts.json` — тримати саме так.

## 6. Операційні процедури

```bash
systemctl status qradar-middleware qradar-poller.timer      # стан
journalctl -u qradar-middleware -f                          # вердикти в реальному часі
tail -f /opt/qradar-middleware/poller.log                   # черга поллера
python3 tests/smoke_test.py                                 # перед комітом
```

Деплой: `git push origin main` → cron `autoupdate.sh` (хвилини 9,19,29,39,49,59)
підхоплює коміт, ставить залежності, прогоняє смоук-гейт, рестартує, перевіряє
health, при провалі відкатує. Негайно — `./deploy.sh` на хості.

## 7. Відомі проблеми, обмеження, борг

- **Пропускна здатність після ресету (2026-08-25).** Обсяг 1534 → 4838 офенсів/добу.
  `max_aql_lenses_per_offense: 2` прибрав Ariel-503 (18 → 0) і `AQL timeout` (5 → 0).
  Далі вузьке місце — llm01: ~30 с на офенс, бо після правок AQL модель викликається майже
  завжди (раніше 92% закривались без неї). Лікується паралельним поллером
  (`poller_concurrency`, дефолт 3) — запис 2026-08-25-b.

- **Поллер насичений у бізнес-години.** Ліміт 100 офенсів/ран, вікно 48 год. Черга
  спорожняється лише в тихі години; підняття ліміту без паралелізму не допоможе —
  ран послідовний (~9 хв на 100 офенсів).
- **Джерело потоку (частково вилікувано 2026-08-24).** UC-07-1 після портового тесту в
  консолі дає **0 офенсів/год** (було 379); загальний потік упав 573 → 153/год, добовий
  обсяг ~9–11 тис. → 1534. Тепер найбільший генератор — UC-05-1 (~28/год).
- **Беклог скинуто 2026-08-24** (запис -d): закрито 27 887 офенсів. Причина — сигнал
  UC-05-1 лежав у трьох офенсах, відкритих із квітня (68 млн подій на 8.8.8.8), які поллер
  за `start_time > -48 год` не міг вибрати в принципі. Після ресету свіжі офенси потрапляють
  у вікно; перша бойова валідація дала `DNS_Policy_Bypass` 0.45 на 8.8.8.8.
- **Ризик повторення:** якщо нові UC-05-1 знову стануть довгоживучими, через місяці
  повернемось у ту саму точку. Потрібен коалесценс-таймаут у правилі. Пайплайн від цього
  вже захищений стелею `max_aql_span_hours` (запис -e), але сам сигнал знову випаде з вікна
  поллера — стеля лікує зациклення, не невидимість.
- **Покриття (переміряно 2026-08-27).** Відкритих офенсів 1663, усі свіжіші за 7 днів.
  З них **943 (57%) не матчаться в `prompts.json` узагалі**, ще **297 (18%) матчаться, але
  старші за 48 год**, тобто випали з вікна поллера й уже не будуть узяті. Вибірка на 150
  офенсах: 86% відкритих не мають жодної нотатки «AI Analysis».
  Найбільший непокритий бакет — `Suspicious Activity Followed by Endpoint Administration
  task` (641) — заведено 2026-08-27. Лишаються без ключа: `IRC Connections` (95),
  `Login failure to an expired account` (32), `Potential Exfiltration of Stored Credentials
  from Browsers` (30), `Suspicious Number of Same User Logins to Multiple Devices` (26),
  `Abnormal Parent for a System Process` (23), `Detected a Service Binary Path Changed` (22),
  `Suspicious Web Server Activities` (21).
  Дірка «покрито, але поза вікном» — системна: лікується або підняттям
  `LOOKBACK_TIME_MS`, або окремим догінним проходом. Наразі не зроблено.
- **Опис офенсу мутує** — QRadar переписує його під останнє спрацьоване правило,
  тож ключ матчингу нестабільний у часі. Частково знешкоджено мульти-лінзовим
  збором подій (див. запис змін від 2026-08-21-c): який саме ключ матчнувся першим,
  тепер впливає лише на вибір промпту, а не на те, які докази дійдуть до моделі.
- **Вартість мульти-лінзи.** Композит = кілька пошуків в Ariel на один офенс
  (стеля — `max_aql_lenses_per_offense`, дефолт 3). Якщо навантаження на Ariel
  зросте — знижувати цей ключ, він на це й зроблений.
- **Черга аналітика (2026-08-27).** Призначених відкритих офенсів — 14 (було 0 на 26.08).
  Обсяг за 7 днів: 32 055 оброблених, 114 `AQL_ERROR` (0.36%), 95 `NO_EVENTS`, 252 ескалації
  на Vertex. 53% обсягу (16 872) закрив `close_on_empty` ще до виклику моделі — тобто основне
  навантаження несуть бенін-фільтри в AQL, а не LLM.
- Немає CI й лінтера — лише `tests/smoke_test.py`, який гейтить деплой.
- 12 рядків залипли в статусі `PROCESSING` (найстаріший з квітня) — шкоди не роблять.

## 8. Історія змін

- [2026-08-27 — юзкейс «Suspicious Activity Followed by Endpoint Administration Task»](changes/2026-08-27-endpoint-admin-task-usecase.md)
- [2026-08-27 — FP у черзі: claude.exe і «C2-беконінг» відеоспостереження](changes/2026-08-27-fp-claude-exe-ta-cctv-c2.md)
- [2026-08-27 — лід по DRT07 закрито, бенін](changes/2026-08-27-drt07-lead-zakryto.md)
- [2026-08-25 — пропускна здатність: паралельний поллер + юзкейс ransomware/file-decode](changes/2026-08-25-b-propusk-poллера.md)
- [2026-08-25 — close_on_empty більше не залежить від max_aql_lenses_per_offense](changes/2026-08-25-a-close-on-empty-ne-zalezhyt-vid-konfigu.md)
- [2026-08-24 — стеля на розмах вікна AQL (max_aql_span_hours)](changes/2026-08-24-e-stelya-vikna-aql.md)
- [2026-08-24 — ресет стану офенсів + перша бойова валідація UC-05-1](changes/2026-08-24-d-reset-stanu-ofensiv.md)
- [2026-08-24 — UC-05-1: поріг обсягу для тунелювання + клас internal-unlisted](changes/2026-08-24-c-uc05-porih-obsyagu.md)
- [2026-08-24 — UC-05-1: AQL і промпт переписані під питання правила](changes/2026-08-24-b-uc05-aql-prompt.md)
- [2026-08-24 — тюнінг правил: UC-07-1 вимкнено як джерело потоку, звірено allowlist UC-05-1](changes/2026-08-24-a-tyuning-uc07-uc05.md)
- [2026-08-21 — tier-2 ескалація теж бере всі лінзи](changes/2026-08-21-d-tier2-multi-lens.md)
- [2026-08-21 — мульти-лінзовий збір подій на композитних офенсах + блок SIP-сканера](changes/2026-08-21-c-multi-lens-kompozyty.md)
- [2026-08-21 — дедлайн полінгу AQL, прибирання Ariel-пошуків, конфігуровані вікна](changes/2026-08-21-b-aql-deadline-ariel-cleanup-vikna.md)
- [2026-08-21 — аудит потоку офенсів і тріаж 10 нерозібраних](changes/2026-08-21-a-audyt-potoku-ofensiv.md)
