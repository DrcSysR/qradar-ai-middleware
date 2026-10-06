# 2026-10-06 — два FIRST CHECK у брутфорс-лінзах: самоавтентифікація брокера RDS (V-SRV01) і PAM fall-through на Linux

## Як знайшлося

Розбір інцидентів з оцінкою > 0.6 за 01–06.10. Два шаблони давали «брутфорс 0.7»
без жодної атаки:

1. **172.17.61.41 = V-SRV01 (RD Connection Broker)** — лінза `UC-ME Block login bruteforce`
   (`btnt_winauth.md`), `WinAuth_Bruteforce_Confirmed` 0.7 кілька разів на добу.
2. **oleksandr.lakodey** — лінзи UC-01-1 / `user_spray`, `Distributed_Bruteforce_Or_Botnet`
   0.7 з поясненням «Multiple external IPs…». Зовнішніх IP у даних не було взагалі.

## Що це насправді

**V-SRV01.** Подія 4648 на брокері: служба `tssdis.exe` (`NETWORK SERVICE`) передає явний
обліковий запис `MODERN\V-SRV01` (без `$`) і стукає на себе та на сесійні хости (V-SRV06).
NTLM → 4625 `0xC0000064` (такого користувача немає), KDC повторює як `V-SRV01$` → 4771 `0x18`.
Обсяг іде за кількістю RDP-підключень (вночі 4–20/год, удень 180–280/год), триває щонайменше
з 07.08. Машинний акаунт здоровий (успішні TGT, `Test-ComputerSecureChannel -Repair` = True).
Де саме брокер зберіг цей логін, не знайдено: його немає ні в реєстрі RDS, ні в GPO, ні в `cmdkey`.
Користувачі не страждають. Рішення власника: прибрати шум на боці SIEM.

**lakodey.** DVL43 (172.17.64.43) → VIDEO.modern.org (192.168.48.207), 204 SSH-сесії
01.10 з 13:10 до 15:14. Кожна сесія = `pam_unix(sshd:auth): authentication failure` + `Accepted
password` з того самого PID sshd за одну секунду: локальний модуль падає, доменний
(SSSD/Kerberos) приймає той самий пароль. Лічильник «Authentication Failure» = «Accepted
Password for User» = 204.

## Що зроблено

- **`prompts/btnt_winauth.md`** — FIRST CHECK: Source_IP `172.17.61.41` + усі невдалі
  іменовані користувачі = `V-SRV01`/`V-SRV01$` (порожній username допускається лише для
  рядків Kerberos pre-auth / WFP — QRadar не витягує для них ім'я) + лише Windows-події →
  0.1 `Benign_RDS_Broker_Selfauth`. Низька оцінка прибирає IP сервера з
  ME-PA-Suspicious-IP-Addresses (серверні мережі за політикою не блокуємо).
- **`prompts/btnt_user_spray.md`**, **`prompts/67500646.md`** — FIRST CHECK
  `Benign_PAM_Fallthrough` 0.1: внутрішнє джерело + Linux/SSH-невдачі + у тій самій парі
  джерело→ціль приблизно стільки ж `Accepted Password` для того ж користувача. Плюс пряма
  заборона описувати джерела як «зовнішні/множинні», якщо цього немає в рядках.

Поля, на які спираються перевірки, звірено з живим виводом `btnt_ip_review.aql` та
`btnt_user_review.aql` 06.10.

## Межі

- Перевірка V-SRV01 прив'язана до конкретного IP та імені. Інший сервер з такою самою
  поведінкою пройде звичайні бенди.
- PAM-перевірка не спрацьовує, якщо невдач помітно більше, ніж успішних входів: справжній
  перебір на тому ж хості залишається видимим.
