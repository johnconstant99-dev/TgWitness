import copy
from pathlib import Path
import sys
import tempfile
import time

import httpx
from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.access import POLICY, Refused, check
from tgwitness.showcase_verify import verify
from tgwitness.verify import fingerprint
from tools.check_browser import RunningApp

CHANNEL = -1001234567890
PRIVATE = -1001234567891
MARKER = "DO_NOT_SHARE_PRIVATE_FIELD"
TEXT = '<img src=x onerror="window.injected=true"> Public announcement: meeting at 16:00.'


def seed(store):
    store.set_target(CHANNEL, "Public research channel", "channel", True)
    store.set_target(PRIVATE, MARKER, "channel", True)
    store.append("source.profile", {"kind": "channel", "title": "Public research channel", "username": "public_fixture",
                                  "raw": {"private": MARKER}, "invite_link": MARKER}, CHANNEL)
    store.append("source.profile", {"kind": "channel", "title": MARKER, "username": None}, PRIVATE)
    for n in range(1, 37):
        store.append("message.new", {"text": TEXT if n == 36 else "Public message " + str(n),
                                    "sender_id": 777123456, "has_media": True,
                                    "sender_observation": {"id": 777123456, "username": MARKER, "phone": MARKER,
                                                           "display_name": MARKER, "avatar": MARKER},
                                    "forward": {"from_name": MARKER}, "raw": {"secret": MARKER},
                                    "entities": [{"user_id": 777123456}], "filename": MARKER}, CHANNEL, n, 777123456)
    store.append("message.edited", {"text": "Meeting moved to 17:30.", "sender_id": 777123456,
                                   "sender_observation": {"display_name": MARKER}}, CHANNEL, 36)
    store.append("message.deleted", {"deleted_by": MARKER, "raw": MARKER}, CHANNEL, 36)
    store.append("message.new", {"text": MARKER}, PRIVATE, 1)


def body():
    return {"label": "Public observation", "showcase": True, "permissions": ["view"],
            "workspaces": {"default": [CHANNEL]}, "max_sessions": 100}


def rejected(call):
    try:
        call()
    except (ValueError, InvalidSignature, Refused):
        return
    raise AssertionError("Expected refusal")


def main():
    with tempfile.TemporaryDirectory(prefix="showcase-") as scratch, RunningApp(Path(scratch), demo=True) as server:
        state = server.app.state
        seed(state.store)
        original = state.store.db.execute("SELECT payload,hash FROM events WHERE chat_id=? AND message_id=36 "
                                          "AND kind='message.new'", (CHANNEL,)).fetchone()
        admin = {"Authorization": "Bearer " + state.vault.token}
        with httpx.Client(base_url=server.url, timeout=30) as http:
            assert http.get("/api/showcase/manage").status_code == 401
            managed = http.get("/api/showcase/manage", headers=admin)
            assert managed.status_code == 200, managed.text
            assert [c["chat_id"] for c in managed.json()["channels"]] == [CHANNEL]
            preview = http.post("/api/showcase/preview", headers=admin, json=body())
            assert preview.status_code == 200, preview.text
            assert not state.access.grants, "Preview must not create access"
            assert MARKER not in preview.text
            for changes in ({"all_workspaces": True}, {"workspaces": {"default": None}},
                            {"permissions": ["view", "export"]}, {"workspaces": {"default": [PRIVATE]}},
                            {"workspaces": {"default": [123456]}}):
                result = http.post("/api/access/grants", headers=admin, json={**body(), **changes})
                assert result.status_code == 422, (changes, result.text)
            issued = http.post("/api/access/grants", headers=admin, json=body()).json()
            login = http.post("/api/access/login", json={"token": issued["token"]})
            assert login.status_code == 200, login.text
            auth = {"Authorization": "Bearer " + login.json()["session"]}
            assert login.json()["me"]["permissions"] == ["showcase"]
            principal = state.access.resolve(login.json()["session"], "127.0.0.1")
            for path, rule in POLICY.items():
                if rule[0] != "showcase":
                    rejected(lambda rule=rule: check(principal, "default", rule, {"chat_id": CHANNEL}))
            for path in ("/api/status", "/api/profiles", "/api/events", "/api/chats",
                         f"/api/chats/{CHANNEL}/messages", f"/api/chats/{CHANNEL}/profile",
                         f"/api/chats/{CHANNEL}/dossier", "/api/access", "/api/network/policy", "/api/stream",
                         "/api/export/json", "/api/avatar/777123456", "/api/media/" + "a" * 64,
                         "/api/showcase/manage"):
                assert http.get(path, headers=auth).status_code == 403, path
            assert http.post("/api/collector/start", headers=auth, json={}).status_code == 403
            assert http.post("/api/showcase/preview", headers=auth, json=body()).status_code == 403
            assert http.get("/api/showcase?challenge=" + "a" * 32 + "&ws=../other", headers=auth).status_code == 404
            response = http.get("/api/showcase?challenge=" + "a" * 32, headers=auth)
            assert response.status_code == 200, response.text
            assert MARKER not in response.text and str(PRIVATE) not in response.text
            first = response.json()["workspaces"][0]
            assert first["statement"]["counts"]["message.new"] == 36
            assert verify(first, fingerprint(state.vault.public_key))["continuity"] == "first observed boundary"
            path = f"/api/showcase/default/chats/{CHANNEL}"
            feed = http.get(path, headers=auth)
            assert feed.status_code == 200, feed.text
            assert MARKER not in feed.text and "777123456" not in feed.text
            items = feed.json()["statement"]["items"]
            assert items[0]["kind"] == "message.deleted"
            assert items[0]["retained"]["text"] == "Meeting moved to 17:30."
            assert items[0]["retained"]["profile"] == "Redacted"
            assert items[1]["kind"] == "message.edited" and items[2]["text"] == TEXT
            older = http.get(path, params={"before": feed.json()["statement"]["next_before"]}, headers=auth).json()
            assert not {i["seq"] for i in items} & {i["seq"] for i in older["statement"]["items"]}
            assert len(http.get(path, params={"message_id": 36}, headers=auth).json()["statement"]["items"]) == 3
            for kind in ("edited", "deleted"):
                filtered = http.get(path, params={"kind": kind}, headers=auth).json()["statement"]["items"]
                assert len(filtered) == 1 and filtered[0]["kind"] == "message." + kind
            for bad in ({"limit": 500}, {"before": -1}, {"message_id": 0}, {"kind": "source.profile"}):
                assert http.get(path, params=bad, headers=auth).status_code == 422
            assert http.get(f"/api/showcase/default/chats/{PRIVATE}", headers=auth).status_code == 404
            assert http.get("/api/showcase/" + "1" * 32, params={"challenge": "a" * 32}, headers=auth).status_code == 403
            state.store.append("message.new", {"text": "Another public observation."}, CHANNEL, 37)
            second = http.get("/api/showcase/default", headers=auth, params={"challenge": "b" * 32,
                              "from_count": first["statement"]["checkpoint"]["statement"]["event_count"]}).json()
            pair = {"format": "tgwitness-showcase-pair-v1", "current": second, "previous": first}
            assert verify(pair, fingerprint(state.vault.public_key))["continuity"] == "consistent with previous snapshot"
            forged = copy.deepcopy(pair)
            forged["current"]["statement"]["counts"]["message.new"] += 1
            rejected(lambda: verify(forged, fingerprint(state.vault.public_key)))
            rejected(lambda: verify(pair, "0" * 64))
            wrong_label = copy.deepcopy(first)
            wrong_label["fingerprint"] = "0" * 64
            rejected(lambda: verify(wrong_label, fingerprint(state.vault.public_key)))
            assert http.get("/api/showcase/default", headers=auth,
                            params={"challenge": "a" * 32, "from_count": 10**12}).status_code == 409
            downgraded = http.patch("/api/access/grants/" + issued["id"], headers=admin, json={**body(), "showcase": False})
            assert downgraded.status_code == 422, downgraded.text
            entry = state.profiles.entries["default"]
            live_app, entry["app"] = entry["app"], None
            try:
                unavailable = http.get("/api/showcase?challenge=" + "d" * 32, headers=auth).json()
                assert unavailable["unavailable"] == ["default"] and not unavailable["workspaces"]
            finally:
                entry["app"] = live_app
            state.store.append("source.profile", {"kind": "channel", "username": None}, CHANNEL)
            assert http.get(path, headers=auth).status_code == 404
            hidden = http.get("/api/showcase?challenge=" + "c" * 32, headers=auth).json()["workspaces"][0]
            assert not hidden["statement"]["channels"] and not any(hidden["statement"]["counts"].values())
            state.access.revoke(issued["id"])
            assert http.get("/api/showcase?challenge=" + "a" * 32, headers=auth).status_code in (401, 403)
            state.store.append("source.profile", {"kind": "channel", "title": "Public channel", "username": "public_fixture"}, CHANNEL)
            expiring = http.post("/api/access/grants", headers=admin, json=body()).json()
            logged = http.post("/api/access/login", json={"token": expiring["token"]}).json()
            state.access.grant(expiring["id"])["expires_at"] = time.time() - 1
            assert http.get("/api/showcase?challenge=" + "a" * 32,
                            headers={"Authorization": "Bearer " + logged["session"]}).status_code in (401, 403)
            assert http.get("/api/status", headers=admin).status_code == 200
            after = state.store.db.execute("SELECT payload,hash FROM events WHERE chat_id=? AND message_id=36 "
                                           "AND kind='message.new'", (CHANNEL,)).fetchone()
            assert tuple(original) == tuple(after), "Disclosure must not rewrite original records"
    print("Showcase: scope, public-profile gate, raw-route denial, redaction, paging, signatures, continuity and revocation passed.")


if __name__ == "__main__":
    main()
