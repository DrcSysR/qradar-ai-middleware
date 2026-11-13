# 2026-11-13 — захист публічних ендпоінтів чат-ботів (netdiag + alarm на nginx2)

**Чому:** огляд «що може зовнішній зловмисник» для `netdiag.modern-expo.ua/chat` і `alarm.modern-expo.ua/api/ext/*`.
Обходу автентифікації не знайдено (токен Google + група / HMAC панелі), але:
1. обидва боти на кожен `Authorization: Bearer <сміття>` спершу качали сертифікати Google
   (`id_token.verify_token` → `_fetch_certs` до розбору токена) — DoS-підсилювач, обмежений лише nginx 10 r/s з IP;
2. на nginx2 `location ^~ /api/ext/` (`allow all`) відкривав зовні **весь** API панелі me-control,
   разом із `/api/ext/action` (зміна стану тривоги), під захистом лише HMAC;
3. дії на PA з netdiag (зняти wan-block / tmp-inet) бачили лише в `pa_actions` — зламаний акаунт noc@ ніхто б не помітив.

**Зроблено:**
- `netdiag_bot.py`: `verify_chat_token` — спершу локальна перевірка форми JWT (3 base64url-частини, довжини,
  `alg=RS256`, `kid`), без мережі; сертифікати Google (`oauth2/v1/certs`) — у кеші за `Cache-Control max-age`
  (≤ 6 год), невідомий `kid` перекачує не частіше раз на 60 с (і після невдачі — теж пауза); підпис/aud/exp —
  `google.auth.jwt.decode`, далі як і було iss/email `chat@system…`/email_verified.
  Перевірено на mdlwr01: сміття відкидається за ~40 мс без мережі, 5 запитів з невідомим `kid` — жодного перекачування.
- `netdiag_pa.py`: `execute` після дії шле коротке повідомлення у вебхук `netdiag_pa_notify_webhook`
  (новий ключ `config_schema`, секрет лише в config.json; URL перевіряється регекспом
  `chat.googleapis.com/v1/spaces/…/messages?…`, у журнал не пишеться; відправка у фоновому потоці, 10 с).
  Порожній ключ = вимкнено.
- nginx2 `alarm.conf`: з `location ^~ /api/ext/` прибрано `allow all` — тепер успадковує серверний allowlist
  (LAN + GlobalProtect). Публічними лишились тільки `= /api/ext/chat`, `= /api/ext/notify`, `= /api/ext/ukrainealarm`.
  Зовнішні виклики `/api/ext/state|action|journal` були лише від старого Cloud Run-бота (34.96.x, останній 04.11)
  і сканера; бот у LAN (172.17.61.108) з 06.11 ходить у панель напряму, повз nginx2.
  Бекап `/root/alarm.conf.bak-20261113-apiext`.

**Не зроблено (поза цим репо / за Віктором):**
- alarm-бот (`~/claude-work/gcp/chat-alert-bot/src/auth.py`) — та сама правка кешу сертифікатів; `/notify` також
  приймає aud gcloud CLI (`32555940559…`) — прибрати, якщо оператори не шлють через `gcloud auth print-identity-token`.
- `/api/ext/ukrainealarm` — публічний без автентифікації за задумом; треба підтвердження, що обробник панелі
  не вірить тілу і склеює часті виклики (інакше потік запитів витрачає ліміт ключа UkraineAlarm).
- ~~Старий Cloud Run-сервіс бота~~ — вимкнено (підтвердив власник, 2026-11-13).

**Перевірено після деплою:** справжній токен Google Chat приймається (діагностика `#cbc312` 08:45, 7.7 с), відмов немає.

**Відкат:** netdiag — `git revert`; nginx2 —
`cp -p /root/alarm.conf.bak-20261113-apiext /etc/nginx/vhosts.d/alarm.conf && nginx -t && systemctl reload nginx`.
