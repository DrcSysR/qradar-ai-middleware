# 2026-09-23 — AQL у тілі POST: ransomware-лінза 40 разів за 3 доби падала з 414 Request-URI Too Long

## Як знайшлося

Розбирали чергу аналітика. Офенс **#1431150** (KDR02, композит `RunDLL32 Outbound` +
`File Decode or Download` + `Mailto Ransomware`) мав вердикт 0.8 `Suspected_Rundll32_C2`
з приміткою *«Evidence: GENERIC query (use-case AQL returned nothing)»*. Ручний розбір:
`rundll32.exe` зі стокових DLL (`AppXDeploymentExtensions.OneCore.dll,ShellRefresh`,
`PcaSvc.dll`, `Startupscan.dll`) з домашньої мережі стукав у **188.163.216.101:443 — нашу
власну публічну адресу** (PA бачить на ній лише зовнішній скан-шум), і так само роблять
ще 20 воркстейшенів різних користувачів. `File Decode` = msiexec оновлює Adobe Acrobat +
`claude.exe` ×20 змін creation time. Чистий FP.

Але **обидві лінзи це вже фільтрують**: `rundll32_outbound.aql` має
`NOT INCIDR('188.163.216.96/28')`, `ransomware_behavior.aql` — Adobe/claude.exe. Обидві мали
віддати порожньо, усі три лінзи мають `close_on_empty` → офенс мав закритись на 0.0 сам.

У лозі за 21.09 09:42:

```
ERROR AQL Error: <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
WARNING ⚠️ Офенс 1431150: AQL не виконався для ['ransomware_behavior.aql'] — close_on_empty знято.
INFO ↩️ … без подій — пробую генеричний default.aql.
INFO ✅ … генеричний AQL дав 18 подій — аналізуємо на них.
```

Тобто логіка композита спрацювала **правильно і консервативно** (лінза впала = «невідомо»,
не «чисто» — запис 2026-08-21-c) — але сама лінза падала не через Ariel.

## Механізм

`fetch_data_from_qradar` слав AQL у **URL**: `POST /api/ariel/searches?query_expression=…`.
Apache перед QRadar має `LimitRequestLine` 8190 байт. Після серії бенін-фільтрів у
вересні (Opera, Autodesk, Adobe, Chrome/OneDrive/YourPhone — записи 09-1x)
`ransomware_behavior.aql` виріс до **8842 байт у URL-кодуванні** (raw 4868). Apache
відповідає HTML-сторінкою `414 Request-URI Too Long` — не JSON, тому в лозі лише
`<!DOCTYPE HTML…`, без коду.

Масштаб за 3 доби: **282** HTML-відповіді від Ariel, **40** падінь саме
`ransomware_behavior.aql` (єдина лінза за лімітом; наступна — `endpoint_admin_task.aql`
5936 байт, запас невеликий). Кожне падіння = ransomware/File-Decode композит іде на
generic AQL без бенін-фільтрів і отримує 0.7–0.8 від моделі на сирих подіях. Це частина
беклогу `File Decode or Download` (581 відкритих на 23.09).

## Що зроблено

- **AQL іде в тілі POST** як `application/x-www-form-urlencoded` (`data={"query_expression":
  aql}`). Перевірено на проді: form-body → `201`, JSON-body → `422`, URL → `201`. У тілі
  практичного ліміту на довжину немає.
- Переноси рядків з відступами стискаються в один пробіл перед відправкою (літерали
  всередині рядка не чіпаються) — запас і читабельніший debug-лог.
- У лог помилки AQL додано ім'я файлу, довжину запиту і HTTP-код — `AQL Error
  (ransomware_behavior.aql, 4868 chars, HTTP 414)` замість голого HTML.

## Що далі (не зроблено тут)

Офенси, оцінені за 3 доби на generic-доказах через цей 414, уже `PROCESSED` з 0.7–0.8 і
відкриті — черга їх не переоцінить. Догінний прохід `tools/catchup.py --force` по лінзі
`ransomware_behavior` після деплою перерахує їх на правильних AQL; більшість має піти в
`close_on_empty` 0.0. Окремо: `endpoint_admin_task.aql` теж великий — у тілі це вже не
має значення, але це нагадування, що бенін-фільтри в AQL мають ціну.
