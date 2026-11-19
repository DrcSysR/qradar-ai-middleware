"""cortex_bot v2: list/detail cards, close flow (kill-switch, validation, audit), investigate.
Run: python -m pytest tests/test_cortex_bot.py   (no network: Cortex/QRadar/Vertex are mocked)."""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cortex_bot as cb  # noqa: E402

INC = {"incident_id": "613", "severity": "medium", "description": "Scan Detection", "creation_time": 1795080992000,
       "hosts": ["172.17.106.42:172.17.106.42"], "users": [], "alert_count": 1, "status": "new",
       "incident_sources": ["PAN NGFW"], "xdr_url": "https://x.xdr/incident-view?caseId=61"}
ALERT = {"name": "SCAN: Host Sweep", "category": "Scan", "severity": "medium", "action_pretty": "Detected", "host_name": "h1"}


def cfg(**kw):
    c = dict(cb.DEFAULTS)
    c["cortexbot_audit_db"] = os.path.join(tempfile.mkdtemp(), "a.db")
    c.update(kw)
    return c


def all_buttons(cards):
    out = []
    def walk(x):
        if isinstance(x, dict):
            if "onClick" in x and "text" in x:
                out.append(x)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(cards)
    return out


def test_case_list_has_three_buttons_per_item(monkeypatch):
    monkeypatch.setattr(cb, "cortex_incidents", lambda c, h: [dict(INC, incident_id=str(i)) for i in range(10)])
    monkeypatch.setattr(cb, "db_safe", lambda *a, **k: [])
    cards, title = cb.case_list_card(cfg(), 0)
    fns = [b["onClick"]["action"]["function"] for b in all_buttons(cards)]
    assert fns.count("d_case") == 6 and fns.count("i_case") == 6 and fns.count("c_case") == 6
    assert "r_review" in fns and "10" in title          # "Ще" button + total count
    cards2, _ = cb.case_list_card(cfg(), 6)
    assert [b["text"] for b in all_buttons(cards2)].count("Деталі") == 4


def test_case_detail_structure(monkeypatch):
    monkeypatch.setattr(cb, "cortex_case", lambda c, i: {"inc": INC, "alerts": [ALERT], "net": [{"network_remote_ip": "1.2.3.4", "network_remote_port": 53}], "files": []})
    monkeypatch.setattr(cb, "db_safe", lambda *a, **k: [("suspicious", "щось", "перевірити")])
    cards, _ = cb.case_detail_card(cfg(), "613")
    heads = [s.get("header") for s in cards[0]["card"]["sections"]]
    assert heads[0] == "Огляд" and any("Автоматичний" in (h or "") for h in heads) and any("Алерти" in (h or "") for h in heads)
    assert any(b.get("onClick", {}).get("openLink") for b in all_buttons(cards))


def test_close_card_respects_killswitch():
    off = cb.close_card("case", "613", cfg())
    assert not [b for b in all_buttons(off) if b["onClick"]["action"].get("function") == "x_case"]
    on = cb.close_card("case", "613", cfg(cortexbot_write_enabled=True))
    assert len([b for b in all_buttons(on) if b["onClick"]["action"].get("function") == "x_case"]) == len(cb.CORTEX_CLOSE)


def test_close_case_blocked_when_disabled(monkeypatch):
    called = []
    monkeypatch.setattr(cb, "cortex_call", lambda *a, **k: called.append(1))
    assert "вимкнено" in cb.do_close_case(cfg(), "a@b.c", "613", "resolved_other")
    assert not called


def test_close_case_ok_and_audited(monkeypatch):
    c = cfg(cortexbot_write_enabled=True)
    calls = []
    monkeypatch.setattr(cb, "cortex_case", lambda c_, i: {"inc": {"status": "new"}})
    monkeypatch.setattr(cb, "cortex_call", lambda cf, path, data, admin=False, timeout=60: calls.append((path, data, admin)))
    out = cb.do_close_case(c, "u@modern-expo.com", "613", "resolved_false_positive")
    assert out.startswith("✅") and calls[0][2] is True and calls[0][1]["update_data"]["status"] == "resolved_false_positive"
    import sqlite3
    rows = sqlite3.connect(c["cortexbot_audit_db"]).execute("SELECT user, action, target, result FROM cortex_bot_audit").fetchall()
    assert rows == [("u@modern-expo.com", "close_case", "613", "ok")]


def test_close_case_already_resolved_is_noop(monkeypatch):
    monkeypatch.setattr(cb, "cortex_case", lambda c_, i: {"inc": {"status": "resolved_other"}})
    monkeypatch.setattr(cb, "cortex_call", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not write")))
    assert "уже має статус" in cb.do_close_case(cfg(cortexbot_write_enabled=True), "u@x.y", "613", "resolved_other")


def test_close_rejects_bad_params():
    c = cfg(cortexbot_write_enabled=True)
    assert "Некоректні" in cb.do_close_case(c, "u", "613", "drop table")
    assert "Некоректні" in cb.do_close_case(c, "u", "6;13", "resolved_other")
    assert "Некоректні" in cb.do_close_offense(c, "u", "5", "999")


def test_close_offense_409_and_ok(monkeypatch):
    class R:
        def __init__(s, code): s.status_code = code
    seq = [R(409), R(200), R(200)]
    monkeypatch.setattr(cb.requests, "post", lambda *a, **k: seq.pop(0))
    c = cfg(cortexbot_write_enabled=True, qradar_url="https://q", qradar_token="t")
    assert "уже закрито" in cb.do_close_offense(c, "u", "5", "1")
    assert cb.do_close_offense(c, "u", "5", "1").startswith("✅")


def test_investigate_case_formats_and_is_readonly(monkeypatch):
    monkeypatch.setattr(cb, "cortex_case", lambda c, i: {"inc": INC, "alerts": [ALERT], "net": [], "files": []})
    monkeypatch.setattr(cb, "vertex_verdict", lambda c, s, p: {"verdict": "benign", "summary": "шум", "next_step": "нічого"})
    monkeypatch.setattr(cb, "cortex_call", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not write")))
    out = cb.investigate_case(cfg(), "613")
    assert "Дорозслідування" in out and "нічого не закрито" in out
    monkeypatch.setattr(cb, "vertex_verdict", lambda c, s, p: None)
    assert "не дала відповіді" in cb.investigate_case(cfg(), "613")


def test_handle_event_routes(monkeypatch):
    spawned = []
    monkeypatch.setattr(cb, "spawn", lambda coro: (spawned.append(coro.cr_code.co_name), coro.close()))
    monkeypatch.setattr(cb, "rate_ok", lambda c, e: True)
    ev = lambda fn, **p: {"type": "CARD_CLICKED", "common": {"invokedFunction": fn, "parameters": p}, "space": {"name": "spaces/AAA"}, "message": {"thread": {}}}
    r = asyncio.run(cb.handle_event(cfg(), ev("c_case", id="613"), "u@x.y"))
    assert "cardsV2" in r and not spawned                       # confirmation card is synchronous, no API call
    r = asyncio.run(cb.handle_event(cfg(), ev("i_off", id="77"), "u@x.y"))
    assert spawned == ["run_action"] and "Готую" in r["text"]
    assert asyncio.run(cb.handle_event(cfg(), ev("c_case", id="x'"), "u@x.y")) == {}
    assert asyncio.run(cb.handle_event(cfg(), ev("nope"), "u@x.y")) == {}
