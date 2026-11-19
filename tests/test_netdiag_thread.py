import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netdiag_bot as nb  # noqa: E402

EV = {"space": {"name": "spaces/AAA"}, "message": {"thread": {"name": "spaces/AAA/threads/T1"}}}


def test_new_message_reposted_into_menu_thread(monkeypatch):
    posted = []
    monkeypatch.setattr(nb, "chat_post", lambda c, sp, body, th="": posted.append((sp, th, body)) or True)
    r = asyncio.run(nb.in_thread({}, EV, {"actionResponse": {"type": "NEW_MESSAGE"}, "text": "hi"}))
    assert r == {} and posted == [("spaces/AAA", "spaces/AAA/threads/T1", {"text": "hi"})]


def test_other_responses_untouched(monkeypatch):
    monkeypatch.setattr(nb, "chat_post", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no post")))
    for resp in ({"actionResponse": {"type": "DIALOG"}}, {"actionResponse": {"type": "UPDATE_MESSAGE"}, "text": "x"}):
        assert asyncio.run(nb.in_thread({}, EV, resp)) == resp
    nothread = {"space": {"name": "spaces/AAA"}, "message": {}}
    r = {"actionResponse": {"type": "NEW_MESSAGE"}, "text": "x"}
    assert asyncio.run(nb.in_thread({}, nothread, r)) == r              # no thread -> unchanged
    monkeypatch.setattr(nb, "chat_post", lambda *a, **k: False)
    assert asyncio.run(nb.in_thread({}, EV, r)) == r                    # post failure -> sync fallback
