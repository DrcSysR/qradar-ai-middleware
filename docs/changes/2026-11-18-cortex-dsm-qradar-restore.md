# 2026-11-18 — QRadar: відновлено DSM/log source Cortex XDR (канал алертів)

**Було:** розширення `Cortex XDR for QRadar 1.2.0` (id 2491) встановлене, але log source `Cortex XDR @ api-gw` (id 8744, тип 4023, identifier `cortexxdr`) вимкнений, остання подія — серпень 2026; на api-gw ізоляційний syslog-ng-файл лежав як `cortex-xdr.conf.disabled`; LSX `CortexXDRCustom_ext` (id 1003) до log source не прив'язаний.

**Зроблено:**
- **api-gw (172.17.61.183):** `conf.d/cortex-xdr.conf.disabled` → `cortex-xdr.conf` (копії: `/root/cortex-xdr.conf.bak-20260807`, `/root/cortex-xdr.conf.disabled-20261118`), `syslog-ng --syntax-only` OK, `syslog-ng-ctl reload`. Файл зрізає подвійний syslog-хедер Cortex до чистого CEF і шле на QRadar як `<PRI>$DATE cortexxdr CEF:…` (див. memory `cortex-xdr-syslog-fix`).
- **QRadar:** log source 8744 `enabled=true`, `log_source_extension_id=1003` (`CortexXDRCustom_ext`). `requires_deploy=false`, окремий Deploy не потрібен.
- **Перевірка:** синтетичний CEF (`TEST dsm check`, `externalId=TESTDSM001/002`) з api-gw → QRadar: подія потрапила на log source `Cortex XDR @ api-gw`, QID `Cortex XDR Message`, `sourceip` 172.17.61.183, хедер зрізано коректно (SIM Generic не було). `username` для `suser` у тесті не розібрався — перевірити на реальній події (тестові події лишились в Ariel, їх легко відфільтрувати за `TESTDSM`).

**Не підтверджено / лишилось:** з боку Cortex реальні події не надходять — у PA traffic log немає сесій від 34.90.105.250 / 34.90.202.186 → 172.17.61.183 (правило «SSL Syslog; index: 26» їх дозволяє). Перевірити в консолі Cortex: **Settings → Configurations → Notifications → Notification Forwarding** (правило з alerts на syslog-приймач `172.17.61.183` / публічний FQDN, TLS), надіслати тест. Після цього статус log source 8744 стане SUCCESS.

**Межі:** це канал **алертів** (CEF). Інциденти Cortex сюди не доходять — окреме рішення (мідлвар → QRadar подіями), див. обговорення «єдине джерело істини». Щоденний звіт `cortex_xdr_scan` читає Cortex API напряму і від цього каналу не залежить.
