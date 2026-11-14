# 2026-11-14 — Cortex XDR звіт: фільтр мережевих алертів pa-vm

## Що сталося

З 13.11 ~16:30 у Cortex XDR пішли журнали pa-vm (джерело алертів `PAN NGFW`), і консоль почала
створювати кейси (№5–52 за добу). Звіт `cortex_xdr_scan.py` о 09:30 14.11 уперше надіслав у Chat
**136 алертів** (до того — 0 на добу): 135 з них від pa-vm.

Склад за 13.11 16:30 – 14.11 10:10 (141 алерт):
- 97 — атаки ззовні на опубліковані адреси (сканери експлойтів GlobalProtect / Hikvision / Dahua / Exchange
  тощо, ZGrab / Nmap), усі **Prevented (reset)**; кейс 27 — 49 алертів від одного 45.144.52.239;
- 32 — Zone Protection: Flood (часто «Allowed», тобто лише поріг) і «SCAN: Host Sweep» з робочих станцій на
  зовнішні 443 (CDN / iCloud);
- 6 — DNS-шкідники з нашої мережі (DSP11, ns1 172.17.61.157, xdc02 ← 192.168.16.51, 172.20.0.1);
- 6 — агенти (WildFire pulsebrowser.exe на ModernExpoLB, BIOC на adm01, Trumpf на TEH30/TEH142, Lightshot на DVL58).

## Зміна

`cortex_xdr_scan.py` — `network_filter()` перед рештою фільтрів, лише для джерел `cortex_xdr_network_sources`
(`PAN NGFW`):
- категорія містить `cortex_xdr_network_drop_categories` (`Zone Protection`) → відкинути;
- ініціатор (`action_local_ip`) публічний і дія — prevent/block/drop/reset → відкинути
  (`cortex_xdr_network_keep_inbound_blocked: true` повертає їх);
- решта (ініціатор у нашій мережі; незаблокована атака ззовні; ініціатор невідомий) → у звіт.

У звіті для мережевих алертів — рядок `мережа: local:port → remote:port (DNS …, правило «…», зони)` і
рекомендація: для DNS-шкідника за форвардером (ns1 / DC) шукати клієнта в журналі DNS у QRadar.
У лог — `net_noise=N`. Нові ключі додано в `config_schema.SCHEMA`.

## Перевірка

Нова логіка на живих алертах за 48 год (без дедупу та відправки): 141 → **12** (97 `network_inbound_blocked`,
32 `Zone Protection`); лишились 6 DNS-шкідників і 6 агентських. Смоук-тест пройдено.

Кейси в консолі Cortex цей фільтр не прибирає — це окремо (правила виключень / налаштування групування в консолі).
