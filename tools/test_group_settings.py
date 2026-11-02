"""Group settings: members follow the group, keep their own values, return to the group's; all signed."""
import asyncio
import sys
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from check_browser import RunningApp
from tgwitness import group_settings, settings_hub


def session(server):
    token = requests.post(server.url + "/api/access/login", json={"token": server.app.state.vault.token}).json()["session"]
    headers = {"Authorization": "Bearer " + token}

    def call(method, path, body=None, status=200, profile=None):
        prefix = "/profiles/" + profile if profile else ""
        r = requests.request(method, server.url + prefix + "/api/" + path, json=body, headers=headers)
        assert r.status_code == status, (path, r.status_code, r.text)
        return r.json()
    return call


def kinds(store):
    return [row[0] for row in store.db.execute("SELECT kind FROM events ORDER BY seq")]


def test_inheritance(tmp_path):
    with RunningApp(tmp_path) as server:
        call = session(server)
        registry = server.app.state.profiles
        group = call("POST", "profile-groups", {"label": "Harbor case"})["groups"][0]
        gid = group["id"]
        alpha = call("POST", "profiles", {"label": "Alpha", "group": gid})["id"]
        beta = call("POST", "profiles", {"label": "Beta", "group": gid})["id"]
        call("PUT", "profiles/default/group", {"group": gid})
        outsider = call("POST", "profiles", {"label": "Outsider"})["id"]
        members = sorted(["default", alpha, beta])
        view = call("GET", "profile-groups/" + gid + "/settings")
        assert view["values"] == {} and sorted(m["id"] for m in view["members"]) == members
        assert all(m["own"] == [] for m in view["members"])

        # A single collection setting needs the group's goal first: its settings come together.
        call("POST", "profile-groups/" + gid + "/settings/preview", {"values": {"files": "all"}}, 409)

        # The group starts sharing a goal: members that differ are listed, and are overwritten only when chosen.
        plan = call("POST", "profile-groups/" + gid + "/settings/preview", {"values": {"goal": "watch"}})
        assert plan["after"]["goal"] == "watch" and plan["after"]["files"] == "short_media"
        assert {row["id"] for row in plan["members"] if row["status"] == "own"} == set(members)
        call("POST", "profile-groups/" + gid + "/settings", {"values": {"goal": "watch"}, "revision": "stale"}, 409)
        result = call("POST", "profile-groups/" + gid + "/settings",
                      {"values": {"goal": "watch"}, "overwrite": members, "revision": plan["revision"]})
        assert sorted(result["applied"]) == members and not result["failed"]
        for pid in members:
            settings = call("GET", "settings", profile=None if pid == "default" else pid)
            assert settings["goal"] == "watch" and settings["values"]["files"] == "short_media"
            assert settings["inheritance"]["group"]["id"] == gid
            assert {k: v["source"] for k, v in settings["inheritance"]["keys"].items()} == \
                {k: "group" for k in ("goal", *group_settings.HUB)}
        outside = call("GET", "settings", profile=outsider)
        assert outside["inheritance"] is None and outside["goal"] is None

        # Beta changes one value in its own settings: that value becomes its own.
        current = call("GET", "settings", profile=beta)
        current = call("POST", "settings/edit", {"key": "files", "value": "photos", "revision": current["revision"]},
                       profile=beta)
        assert current["inheritance"]["keys"]["files"] == {"value": "photos", "group_value": "short_media", "source": "own"}
        assert current["inheritance"]["keys"]["timestamps"]["source"] == "group"

        # The group changes that value: 2 of 3 follow; Beta keeps its own unless chosen.
        plan = call("POST", "profile-groups/" + gid + "/settings/preview", {"values": {"files": "all"}})
        assert plan["follow"] == 2 and plan["total"] == 3
        own = [row for row in plan["members"] if row["status"] == "own"]
        assert [row["id"] for row in own] == [beta] and own[0]["own"] == {"files": "photos"}
        result = call("POST", "profile-groups/" + gid + "/settings", {"values": {"files": "all"}, "revision": plan["revision"]})
        assert result["kept"] == [beta] and sorted(result["applied"]) == sorted(["default", alpha])
        assert call("GET", "settings", profile=alpha)["values"]["files"] == "all"
        assert call("GET", "settings", profile=beta)["values"]["files"] == "photos"

        # Returning to the group's value.
        result = call("POST", "profile-groups/" + gid + "/settings/adopt", {"profiles": [beta], "keys": ["files"]})
        assert result["applied"] == [beta]
        assert call("GET", "settings", profile=beta)["inheritance"]["keys"]["files"]["source"] == "group"
        call("POST", "profile-groups/" + gid + "/settings/adopt", {"profiles": [outsider]}, 409)
        call("POST", "profile-groups/" + gid + "/settings/adopt", {"profiles": [beta], "keys": ["reports"]}, 409)

        # An edit to the group follows the rules of one workspace: dependent features need consent.
        plan = call("POST", "profile-groups/" + gid + "/settings/preview", {"values": {"outside": False}}, 409)
        plan = call("POST", "profile-groups/" + gid + "/settings/preview",
                    {"values": {"outside": False}, "disable_dependents": True})
        assert plan["after"]["outside"] is False and plan["after"]["timestamps"] is False

        # Parameters, recording, recheck, notification rules and report details are shared the same way.
        reports = {**call("GET", "report-options"), "case_title": "Harbor", "examiner": "A. Analyst"}
        values = {"parameter:snapshot_max": 777, "monitoring": {"messages": True, "edits": True, "deletions": True,
                  "reactions": False, "membership": True}, "recheck": {"recheck_minutes": 30, "recheck_other_minutes": 600},
                  "alert_rules": {"daily": False, "daily_hour": 7}, "reports": reports}
        plan = call("POST", "profile-groups/" + gid + "/settings/preview", {"values": values})
        result = call("POST", "profile-groups/" + gid + "/settings",
                      {"values": values, "overwrite": members, "revision": plan["revision"]})
        assert not result["failed"]
        for pid in members:
            app = registry.entries[pid]["app"]
            store = app.state.store
            assert store.get_setting("parameters")["snapshot_max"] == 777
            assert store.get_setting("monitoring")["reactions"] is False
            assert store.get_setting("recheck_minutes") == 30
            assert store.get_setting("alerts")["daily_hour"] == 7
            assert store.get_setting("report_options")["case_title"] == "Harbor"
            journal = kinds(store)
            assert "group.settings_inherited" in journal and "parameters.changed" in journal
            assert "monitoring.changed" in journal and "recheck.changed" in journal
        assert call("GET", "settings", profile=outsider) and \
            registry.entries[outsider]["app"].state.store.get_setting("parameters", {}).get("snapshot_max") != 777
        panel = kinds(server.app.state.store)
        assert panel.count("profile_group.settings_changed") == 3 and "profile_group.settings_adopted" in panel

        # Stop sharing a setting: members keep their values, the group no longer marks them.
        plan = call("POST", "profile-groups/" + gid + "/settings/preview", {"values": {"reports": None}})
        call("POST", "profile-groups/" + gid + "/settings", {"values": {"reports": None}, "revision": plan["revision"]})
        assert "reports" not in call("GET", "profile-groups/" + gid + "/settings")["values"]
        assert registry.entries[alpha]["app"].state.store.get_setting("report_options")["case_title"] == "Harbor"

        # A workspace added to the group later starts with everything the group shares.
        gamma = call("POST", "profiles", {"label": "Gamma", "group": gid})["id"]
        settings = call("GET", "settings", profile=gamma)
        assert settings["goal"] == "watch" and settings["values"]["files"] == "all"
        assert registry.entries[gamma]["app"].state.store.get_setting("parameters")["snapshot_max"] == 777
        assert all(v["source"] == "group" for v in settings["inheritance"]["keys"].values())

        # A checked route applied to the whole group becomes the group's route; members are compared with it.
        for pid in [*members, gamma]:
            registry.entries[pid]["app"].state.store.set_setting("connection_strategy", {"mode": "warp", "allow_direct": False})
        group_settings.record_route(registry, gid, {"mode": "warp", "allow_direct": False}, members)
        assert call("GET", "settings", profile=gamma)["inheritance"]["keys"]["route"]["source"] == "group"
        registry.entries[gamma]["app"].state.store.set_setting("connection_strategy", {"mode": "direct", "allow_direct": True})
        assert call("GET", "settings", profile=gamma)["inheritance"]["keys"]["route"]["source"] == "own"
        # Copying never changes a route: it needs a connection check.
        result = call("POST", "profile-groups/" + gid + "/settings/adopt", {"profiles": [gamma], "keys": ["route"]})
        assert registry.entries[gamma]["app"].state.store.get_setting("connection_strategy")["mode"] == "direct"

        # Invalid values are refused before anything changes.
        call("POST", "profile-groups/" + gid + "/settings/preview", {"values": {"parameter:snapshot_max": -1}}, 422)
        call("POST", "profile-groups/" + gid + "/settings/preview", {"values": {"nonsense": 1}}, 422)
        call("POST", "profile-groups/" + gid + "/settings/preview", {"values": {"recheck": {"recheck_minutes": -5}}}, 422)
        call("GET", "profile-groups/" + "0" * 32 + "/settings", status=400)


def test_access_by_group(tmp_path):
    with RunningApp(tmp_path) as server:
        call = session(server)
        gid = call("POST", "profile-groups", {"label": "Team"})["groups"][0]["id"]
        inside = call("POST", "profiles", {"label": "Inside", "group": gid})["id"]
        outside = call("POST", "profiles", {"label": "Outside"})["id"]
        call("POST", "access/grants", {"label": "Ghost", "groups": ["f" * 32]}, 422)
        # A showcase opens listed public channels only, never whole accounts of a group.
        call("POST", "access/grants", {"label": "Show", "showcase": True, "groups": [gid]}, 422)
        issued = call("POST", "access/grants", {"label": "Lawyer", "groups": [gid], "permissions": ["view"]})
        assert call("GET", "access")["groups"][0]["id"] == gid
        token = requests.post(server.url + "/api/access/login", json={"token": issued["token"]}).json()["session"]
        headers = {"Authorization": "Bearer " + token}

        def status(pid):
            return requests.get(server.url + "/profiles/" + pid + "/api/status", headers=headers).status_code
        assert status(inside) == 200 and status(outside) == 403
        assert requests.get(server.url + "/api/status", headers=headers).status_code == 403
        later = call("POST", "profiles", {"label": "Later", "group": gid})["id"]
        assert status(later) == 200
        call("PUT", "profiles/" + later + "/group", {"group": None})
        assert status(later) == 403
        call("DELETE", "profile-groups/" + gid)
        assert status(inside) == 403
        grant = next(g for g in call("GET", "access")["grants"] if g["label"] == "Lawyer")
        assert grant["groups"] == []


def test_template_groups_migrate(tmp_path):
    with RunningApp(tmp_path) as server:
        call = session(server)
        registry = server.app.state.profiles
        member = call("POST", "profiles", {"label": "Member"})["id"]
        call("POST", "parameters", {"values": {"snapshot_max": 555}})
        gid = call("POST", "profile-groups", {"label": "Old", "template": "default",
                                              "sections": ["parameters", "recheck"]})["groups"][0]["id"]
        call("PUT", "profiles/" + member + "/group", {"group": gid})
        call("PUT", "profiles/default/group", {"group": gid})
        groups = server.app.state.store.get_setting("profile_groups")
        groups[0].pop("values", None)
        server.app.state.store.set_setting("profile_groups", groups)
        group_settings.migrate(registry)
        shared = call("GET", "profile-groups/" + gid + "/settings")
        assert shared["values"]["parameter:snapshot_max"] == 555 and "recheck" in shared["values"]
        # Nothing changed in the member: it differs, so it keeps its own value.
        own = next(m for m in shared["members"] if m["id"] == member)["own"]
        assert "parameter:snapshot_max" in own
        assert "profile_group.migrated" in kinds(server.app.state.store)
        # Apply still copies from the template, and the group then shares what it copied.
        call("POST", "profile-groups/" + gid + "/apply", {})
        shared = call("GET", "profile-groups/" + gid + "/settings")
        assert all(m["own"] == [] for m in shared["members"])
        assert registry.entries[member]["app"].state.store.get_setting("parameters")["snapshot_max"] == 555


def test_values_are_checked():
    assert group_settings.valid("files", "all") == "all"
    for key, value in (("files", "custom"), ("goal", "spy"), ("timestamps", 1), ("route", {"mode": "teleport"}),
                       ("monitoring", {"messages": "yes"}), ("parameter:snapshot_max", "many")):
        try:
            group_settings.valid(key, value)
        except ValueError:
            continue
        raise AssertionError((key, value))
    # Collecting now or paused stays with each account.
    assert set(group_settings.KEYS) >= set(settings_hub.PRESETS["watch"]) - {"continuous"}
    assert "continuous" not in group_settings.KEYS
    assert asyncio.run(group_settings.apply_member(None, {"route": {"mode": "warp"}}, {}, "test")) is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
