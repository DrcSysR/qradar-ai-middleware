"""Інтерфейс netdiag-бота в Google Chat: меню-картка з кнопками і діалогові вікна.

Кнопки меню відкривають діалоги (`interaction: OPEN_DIALOG`):
  🔎 Діагностика IP   → поле IP/MAC                   → картка діагностики (NEW_MESSAGE)
  🌐 Інтернет         → IP + строк (список) / свої год → tmp-inet на pa-vm  → картка результату
  🧱 Зняти wan-block  → публічний IP                   → unregister wan-block → картка результату
Під карткою діагностики — «🔄 Перевірити ще раз» і «🌐 Інтернет…» (діалог з уже підставленим IP);
для Wi-Fi — «🧠 Розширена аналітика» (черга до llm01, `netdiag_ai.py`).

Діалог — сам по собі підтвердження: людина бачить поля і тисне «Застосувати». Помилки вводу
повертаються в той самий діалог (actionStatus INVALID_ARGUMENT + текст), він не закривається.
Усі значення з форм — недовірений ввід: валідація в `netdiag_pa.validate` / `netdiag.parse_ip`.
"""
from __future__ import annotations

import netdiag
import netdiag_pa

INET_CHOICES = [("1 година", 1), ("4 години", 4), ("8 годин", 8), ("1 день", 24), ("3 дні", 72),
                ("7 днів", 168), ("14 днів", 336), ("30 днів", 720)]


def _icon(name: str) -> dict:
    return {"materialIcon": {"name": name}}


def _act(fn: str, params: dict | None = None, dialog: bool = False) -> dict:
    a = {"function": fn}
    if params:
        a["parameters"] = [{"key": k, "value": str(v)} for k, v in params.items()]
    if dialog:
        a["interaction"] = "OPEN_DIALOG"
    return {"action": a}


def button(text: str, fn: str, params: dict | None = None, dialog: bool = False, icon: str | None = None,
           filled: bool = False) -> dict:
    b = {"text": text, "onClick": _act(fn, params, dialog)}
    if icon:
        b["icon"] = _icon(icon)
    if filled:
        b["type"] = "FILLED"
    return b


# ============================================================================ меню
def home(email: str, pa: bool) -> dict:
    buttons = [button("Діагностика IP", "dlg_diag", dialog=True, icon="search", filled=True)]
    if pa:
        buttons += [button("Інтернет (tmp-inet)", "dlg_inet", dialog=True, icon="public"),
                    button("Зняти wan-block", "dlg_unblock", dialog=True, icon="lock_open")]
    widgets = [
        {"textParagraph": {"text": "Оберіть дію. Можна й просто написати IP у чат — одразу покажу діагностику."}},
        {"buttonList": {"buttons": buttons}},
    ]
    if not pa:
        widgets.append({"textParagraph": {"text": netdiag._c("Дії на Palo Alto вам не доступні — лише діагностика.", netdiag.GREY)}})
    return {"fallbackText": "Меню діагностики мережі",
            "cardsV2": [{"cardId": "home", "card": {
                "header": {"title": "Діагностика мережі", "subtitle": "Wi-Fi · комутатори · NPS · Palo Alto",
                           "imageType": "CIRCLE",
                           "imageUrl": "https://fonts.gstatic.com/s/i/googlematerialicons/lan/v12/24px.svg"},
                "sections": [{"widgets": widgets}]}}]}


def result_actions(ip: str | None, pa: bool, ai: dict | None = None) -> dict:
    """Секція з кнопками під карткою діагностики. ai = {"mac", "ip"} — лише для Wi-Fi: кнопка розширеної
    аналітики несе MAC, знайдений під час діагностики (аналіз іде за MAC, не за IP)."""
    btns = []
    if ai and ai.get("mac"):
        btns.append(button("Розширена аналітика", "dlg_ai", {k: v for k, v in ai.items() if v not in (None, "")},
                           dialog=True, icon="psychology", filled=True))
    if ip:
        btns.append(button("Перевірити ще раз", "run_diag", {"ip": ip}, icon="refresh"))
        if pa:
            btns.append(button("Інтернет…", "dlg_inet", {"ip": ip}, dialog=True, icon="public"))
    btns.append(button("Меню", "show_home", icon="menu"))
    return {"widgets": [{"buttonList": {"buttons": btns}}]}


# ============================================================================ діалоги
def _dialog(title: str, widgets: list, submit_fn: str, submit_text: str, params: dict | None = None) -> dict:
    widgets = widgets + [{"buttonList": {"buttons": [button(submit_text, submit_fn, params, icon="check", filled=True)]}}]
    return {"actionResponse": {"type": "DIALOG", "dialogAction": {"dialog": {"body": {
        "header": {"title": title}, "sections": [{"widgets": widgets}]}}}}}


def _ip_input(name: str, label: str, hint: str, value: str = "") -> dict:
    w = {"textInput": {"name": name, "label": label, "type": "SINGLE_LINE", "hintText": hint}}
    if value:
        w["textInput"]["value"] = value
    return w


def dlg_diag(prefill: str = "") -> dict:
    return _dialog("🔎 Діагностика підключення", [
        _ip_input("ip", "IP або MAC пристрою", "напр. 172.17.104.25 або aa:bb:cc:dd:ee:ff", prefill),
        {"textParagraph": {"text": netdiag._c("Wi-Fi: точка, сигнал, історія 15 хв · кабель: свіч, порт, 802.1X · NPS", netdiag.GREY)}},
    ], "submit_diag", "Діагностувати")


def dlg_inet(prefill_ip: str = "") -> dict:
    items = [{"text": t, "value": str(h), "selected": h == 4} for t, h in INET_CHOICES]
    return _dialog("🌐 Тимчасовий інтернет (tmp-inet)", [
        _ip_input("ip", "Внутрішній IP", "напр. 172.17.40.25", prefill_ip),
        {"selectionInput": {"name": "hours", "label": "Строк", "type": "DROPDOWN", "items": items}},
        _ip_input("custom_hours", "Або свій строк, год (необов'язково)", "напр. 36 — перекриває вибір зі списку"),
        {"textParagraph": {"text": netdiag._c("Тег спливе сам. Лише pa-vm. Дія журналюється.", netdiag.GREY)}},
    ], "submit_inet", "Застосувати")


def dlg_unblock(prefill_ip: str = "") -> dict:
    tags = ", ".join(netdiag_pa.DEFAULTS["netdiag_pa_unblock_tags"])
    return _dialog("🧱 Зняти блокування з зовнішнього IP", [
        _ip_input("ip", "Публічний IP", "напр. 160.238.125.164 (домашній IP співробітника)", prefill_ip),
        {"textParagraph": {"text": netdiag._c(f"Буде знято тег(и): {tags} на pa-vm. Дія журналюється.", netdiag.GREY)}},
    ], "submit_unblock", "Зняти блокування")


def dlg_ai(mac: str, ip: str = "", extra: dict | None = None) -> dict:
    """Скарга перед розширеною аналітикою: фокусує висновок LLM. extra = контекст кнопки (m=wired, sw, ifn, ifi, bp)."""
    import netdiag_ai
    extra = extra or {}
    wired = extra.get("m") == "wired"
    keys = netdiag_ai.WIRED_COMPLAINTS if wired else netdiag_ai.WIFI_COMPLAINTS
    items = [{"text": netdiag_ai.COMPLAINTS[k][:1].upper() + netdiag_ai.COMPLAINTS[k][1:], "value": k, "selected": k == keys[0]}
             for k in keys]
    what = (f"кабель: свіч {extra.get('sw')}, порт {extra.get('ifn')} — події й syslog порту (LibreNMS), автоузгодження з карткою, "
            "інші порти свіча, DHCP, 802.1X/NPS, Palo Alto") if wired else \
        "Wi-Fi (пристрій і інші клієнти точки), DHCP, NPS, Palo Alto"
    return _dialog(f"🧠 Розширена аналітика {ip or mac}", [
        {"selectionInput": {"name": "complaint", "label": "На що скаржаться", "type": "RADIO_BUTTON", "items": items}},
        {"textInput": {"name": "details", "label": "Деталі (необов'язково)", "type": "MULTIPLE_LINE",
                       "hintText": "Який застосунок, де саме (кабінет/цех), коли почалось"}},
        {"textParagraph": {"text": netdiag._c(
            f"Аналіз за MAC {mac} за останню годину: {what}. Результат прийде окремим повідомленням у цей тред.", netdiag.GREY)}},
    ], "submit_ai", "Аналізувати", {"mac": mac, "ip": ip, **extra})


def dialog_error(msg: str) -> dict:
    return {"actionResponse": {"type": "DIALOG", "dialogAction": {"actionStatus": {
        "statusCode": "INVALID_ARGUMENT", "userFacingMessage": msg[:250]}}}}


def dialog_close() -> dict:
    return {"actionResponse": {"type": "DIALOG", "dialogAction": {"actionStatus": {"statusCode": "OK"}}}}


def form_value(event: dict, name: str) -> str:
    fi = ((event.get("common") or {}).get("formInputs") or {}).get(name) or {}
    vals = ((fi.get("stringInputs") or {}).get("value")) or []
    return str(vals[0]).strip()[:64] if vals else ""


def form_text(event: dict, name: str, limit: int = 300) -> str:
    """Як form_value, але для довшого вільного тексту (деталі скарги)."""
    fi = ((event.get("common") or {}).get("formInputs") or {}).get(name) or {}
    vals = ((fi.get("stringInputs") or {}).get("value")) or []
    return " ".join(str(vals[0]).split())[:limit] if vals else ""
