# docs — qradar-ai-middleware

AI-тріаж офенсів QRadar: сервіс читає офенс, підбирає промпт і AQL під правило,
отримує від LLM JSON-вердикт і на його підставі закриває офенс, призначає аналітику
або знімає IP із блок-листа Palo Alto. Прод — `/opt/qradar-middleware` на mdlwr01.

- **[state.md](state.md)** — поточний стан: компоненти, механізми, файли, процедури,
  відомі проблеми. Починати звідси.
- **changes/** — хронологія завершених змін і аудитів (нове зверху).

Керує: скіл `qradar-soc` + `CLAUDE.md` у корені репо.

| Дата | Запис |
|---|---|
| 2026-08-26 | [UC-06-1: FIRST CHECK проти хибних multi-stage compromise](changes/2026-08-26-uc06-firstcheck-fp.md) |
| 2026-08-26 | [File Decode: FIRST CHECK, читання доказів і бенін-фільтр](changes/2026-08-26-file-decode-firstcheck.md) |
| 2026-08-25 | [паралельний поллер + юзкейс ransomware/file-decode](changes/2026-08-25-b-propusk-poллера.md) |
| 2026-08-25 | [close_on_empty більше не залежить від max_aql_lenses_per_offense](changes/2026-08-25-a-close-on-empty-ne-zalezhyt-vid-konfigu.md) |
| 2026-08-24 | [стеля на розмах вікна AQL (max_aql_span_hours)](changes/2026-08-24-e-stelya-vikna-aql.md) |
| 2026-08-24 | [ресет стану офенсів + перша бойова валідація UC-05-1](changes/2026-08-24-d-reset-stanu-ofensiv.md) |
| 2026-08-24 | [UC-05-1: поріг обсягу для тунелювання + клас internal-unlisted](changes/2026-08-24-c-uc05-porih-obsyagu.md) |
| 2026-08-24 | [UC-05-1: AQL і промпт переписані під питання правила](changes/2026-08-24-b-uc05-aql-prompt.md) |
| 2026-08-24 | [тюнінг правил радара: UC-07-1 і allowlist UC-05-1](changes/2026-08-24-a-tyuning-uc07-uc05.md) |
| 2026-08-21 | [tier-2 ескалація теж бере всі лінзи](changes/2026-08-21-d-tier2-multi-lens.md) |
| 2026-08-21 | [мульти-лінзовий збір подій на композитах + блок SIP-сканера](changes/2026-08-21-c-multi-lens-kompozyty.md) |
| 2026-08-21 | [дедлайн полінгу AQL, прибирання Ariel-пошуків, конфігуровані вікна](changes/2026-08-21-b-aql-deadline-ariel-cleanup-vikna.md) |
| 2026-08-21 | [аудит потоку офенсів і тріаж 10 нерозібраних](changes/2026-08-21-a-audyt-potoku-ofensiv.md) |
