"""netdiag_pa: permanent wan-block with description (register without timeout, persistent=1), registry, protection."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netdiag_pa as pa  # noqa: E402


def cfg():
    return {"netdiag_db": os.path.join(tempfile.mkdtemp(), "n.db"), "netdiag_pa_uid_key": "k"}


def test_parse_block_command():
    c = pa.parse_command("блок 45.9.148.10 брутфорс SSH, тікет 12")
    assert c["op"] == "block" and c["ip"] == "45.9.148.10" and "брутфорс SSH" in c["desc"] and "45.9.148.10" not in c["desc"]
    assert pa.parse_command("block 1.2.3.4 x")["op"] == "block"
    assert pa.parse_command("розблокуй 1.2.3.4")["op"] == "unblock"      # unblock is not shadowed by block


def test_validate_block():
    p, e = pa.validate(cfg(), "block", "45.9.148.10", desc="  scan <b>x</b>\n ")
    assert p["desc"].startswith("scan")
    assert "<" not in p["desc"] and ">" not in p["desc"] and "\n" not in p["desc"]
    assert pa.validate(cfg(), "block", "10.0.0.1", desc="abc")[0] is None            # private
    assert pa.validate(cfg(), "block", "188.163.216.99", desc="abc")[0] is None      # own perimeter
    assert pa.validate(cfg(), "block", "185.59.227.218", desc="abc")[0] is None      # own /29
    assert pa.validate(cfg(), "block", "45.9.148.10", desc="")[0]["desc"] == pa.NO_DESC   # description optional
    assert pa.validate(cfg(), "block", "45.9.148.10", 3)[0]["hours"] == 3
    assert pa.validate(cfg(), "block", "45.9.148.10", 99999)[0] is None
    assert len(pa.clean_desc("x" * 500)) == pa.DESC_MAX


def test_block_registers_permanently_and_is_listed(monkeypatch):
    calls = []
    monkeypatch.setattr(pa, "uid_call", lambda c, kind, ip, tag, to: (calls.append((kind, ip, tag, to)) or (True, "success")))
    monkeypatch.setattr(pa, "notify", lambda *a, **k: None)
    c = cfg()
    ok, msg = pa.execute(c, {"op": "block", "ip": "45.9.148.10", "desc": "брутфорс SSH"}, "u@x.y", "a1")
    assert ok and calls == [("register", "45.9.148.10", "wan-block", None)] and "bot-ip-45.9.148.10" in msg
    rows = pa.list_blocks(c)
    assert [(r[0], r[2], r[3]) for r in rows] == [("45.9.148.10", "u@x.y", "брутфорс SSH")]
    ok, _ = pa.execute(c, {"op": "unblock", "ip": "45.9.148.10"}, "u@x.y", "a2")
    assert ok and pa.list_blocks(c) == []


def test_register_message_is_persistent_without_timeout():
    m = pa._uid_message("register", "45.9.148.10", "wan-block", None)
    assert 'persistent="1"' in m and "timeout" not in m


def test_failed_register_is_not_recorded(monkeypatch):
    monkeypatch.setattr(pa, "uid_call", lambda *a: (False, "403"))
    monkeypatch.setattr(pa, "notify", lambda *a, **k: None)
    c = cfg()
    ok, msg = pa.execute(c, {"op": "block", "ip": "45.9.148.10", "desc": "abc"}, "u", "a")
    assert not ok and pa.list_blocks(c) == []


def test_blocks_card_has_unblock_buttons(monkeypatch):
    monkeypatch.setattr(pa, "list_blocks", lambda c, n=15: [("45.9.148.10", 1700000000, "u@x.y", "опис", None), ("45.9.148.11", 1700000000, "u", "т", 1700010800)])
    card = pa.blocks_card({})
    assert "Зняти" in str(card) and "bot-ip-45.9.148.10" in str(card) and "назавжди" in str(card) and "до " in str(card)


def test_quick_command_parsing():
    assert pa.parse_command("блокування") == {"op": "list"}
    assert pa.parse_command("список") == {"op": "list"}
    assert pa.parse_command("зняти блок 1.2.3.4")["op"] == "unblock"
    assert pa.parse_command("розблокувати 1.2.3.4")["op"] == "unblock"
    assert pa.parse_command("блокування 45.9.148.10 тест")["op"] == "block"      # list is exact-match only
    assert pa.parse_command("172.17.1.1") is None


def test_memo_hides_pa_commands_from_non_pa():
    import netdiag_ui as ui
    assert "блок 1.2.3.4" in ui.memo(True) and "блок 1.2.3.4" not in ui.memo(False)
    assert "діагностика" in ui.memo(False)


def test_block_duration_parsing():
    a = pa.parse_command("блок 1.2.3.4")
    assert a["hours"] is None and a["desc"].strip() == ""
    b = pa.parse_command("блок 1.2.3.4 3г")
    assert b["hours"] == 3 and b["desc"].strip() == ""
    c = pa.parse_command("блок 1.2.3.4 2д брутфорс")
    assert c["hours"] == 48 and c["desc"].strip() == "брутфорс"
    d = pa.parse_command("блок 3 год 1.2.3.4")
    assert d["hours"] == 3
    e = pa.parse_command("блок 1.2.3.4 брутфорс тікет 123")        # a bare number in the description is NOT a duration
    assert e["hours"] is None and "123" in e["desc"]
    f = pa.parse_command("блок 1.2.3.4 тікет 3г")                   # unit-number later in the text is not a duration either
    assert f["hours"] is None


def test_timed_block_registers_with_timeout_and_expires_from_list(monkeypatch):
    calls = []
    monkeypatch.setattr(pa, "uid_call", lambda c, kind, ip, tag, to: (calls.append(to) or (True, "success")))
    monkeypatch.setattr(pa, "notify", lambda *a, **k: None)
    c = cfg()
    ok, msg = pa.execute(c, {"op": "block", "ip": "45.9.148.10", "desc": "x", "hours": 3}, "u", "a")
    assert ok and calls == [10800] and "3 год" in msg
    assert pa.list_blocks(c)[0][4] is not None
    monkeypatch.setattr(pa.time, "time", lambda: 9999999999)        # long after the timeout
    assert pa.list_blocks(c) == []


def test_action_log_card_and_paging(monkeypatch):
    monkeypatch.setattr(pa, "notify", lambda *a, **k: None)
    monkeypatch.setattr(pa, "uid_call", lambda *a: (True, "success"))
    c = cfg()
    for i in range(12):
        pa.execute(c, {"op": "block", "ip": f"45.9.148.{i + 1}", "desc": "x", "hours": 3 if i == 0 else None}, "me@x.y", f"a{i}")
    card = pa.log_card(c, 0)
    txt = str(card)
    assert "Журнал дій — 12" in txt and "Старіші" in txt and "Блок" in txt and "45.9.148.12" in txt and "45.9.148.1<" not in txt
    assert "Новіші" in str(pa.log_card(c, 10)) and "Старіші" not in str(pa.log_card(c, 10))
    assert pa.parse_command("журнал") == {"op": "log"}
