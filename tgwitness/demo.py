from datetime import datetime, timedelta, timezone


def seed_demo(store):
    if store.stats()["total"]:
        return
    store.set_setting("demo", True)
    store.set_setting("report_options", {
        "case_title": "Harbor portal · Fictional investigation", "case_id": "HBR-042",
        "notes": "Synthetic demonstration. No Telegram connection. All people, domains and messages in this case are fictional.",
    })
    groups = [(-100100001, "Northstar · Research", "supergroup"),
              (-100100002, "Harbor · Community", "supergroup"),
              (-100100003, "Signal · Announcements", "channel")]
    for cid, title, kind in groups:
        store.set_target(cid, title, kind, True)
    store.append("demo.created", {"synthetic": True, "meaning": "Fictional demonstration; no Telegram connection"})
    people = ("Morgan Reed", "Alex Quinn", "Sam Vale", "Casey Lin")
    # All people, messages and .example addresses below belong to this fictional case.
    texts = [
        "Case HBR-042. Keep the original portal link, later edits and deletion notices together.",
        "Is harbor-check.example the new verification portal? The link arrived in a private message.",
        "Community briefing starts at 16:00 UTC. We will review the reported verification messages.",
        "The same numeric account ID appears in both chats. A changed display name is not a new account.",
        "Support asked me to enter my recovery phrase at https://harbor-check.example/verify. Is that normal?",
        "Updates will be posted here. We do not send private messages asking for recovery phrases.",
        "Compare the saved announcement with its edited version. Keep the source record for each statement.",
        "Please verify your wallet at https://harbor-check.example/verify before the next briefing.",
        "No team member will ask for your recovery phrase. Keep it private.",
        "The request was deleted after we saved it. The captured text is still in the journal.",
        "I was also asked to send a recovery phrase. The message came from an account using the team name.",
        "The earlier verification link has been withdrawn. Check the announcement history before following links.",
        "Working note: one portal link found in the captured messages.",
        "That portal link has changed. Both versions should stay in the record.",
        "Case briefing: https://harbor.example/case/HBR-042. Use the saved messages as source references.",
        "Provisional note: these accounts may share an operator. Needs evidence before attribution.",
        "I saved the original text, the edited link and both deletion notices for review.",
        "Case HBR-042 is ready for review. Refer to the signed archive for the captured records.",
    ]
    edits = {
        2: "Community briefing starts at 17:30 UTC. Time corrected after the first announcement.",
        7: "Please use https://harbor-help.example/support instead. The earlier portal link has been replaced.",
        12: "Working note: two portal links found. Both saved versions are included; attribution remains unconfirmed.",
    }
    now = datetime.now(timezone.utc)
    for i in range(18):
        cid, _, _ = groups[i % 3]
        source = (now - timedelta(minutes=90 - i * 4)).isoformat()
        text = texts[i]
        sender = {"id": 70001 + i % 4, "display_name": people[i % 4],
                  "meaning": "Fictional person in a synthetic demonstration", "synthetic": True}
        store.append("message.new", {"text": text, "sender_id": 70001 + i % 4,
                                    "sender_observation": sender,
                                    "source": "synthetic_demo", "synthetic": True,
                                    "sent_at": source, "has_media": False},
                     cid, 401 + i, 70001 + i % 4, source)
        if i in (2, 7, 12):
            store.append("message.edited", {"text": edits[i],
                                           "sender_id": 70001 + i % 4, "editor_id": None,
                                           "sender_observation": sender,
                                           "source": "synthetic_demo", "synthetic": True},
                         cid, 401 + i, source_at=source)
        if i in (4, 10, 15):
            store.append("message.deleted", {"deleted_by": None, "deletion_time": None,
                                            "synthetic": True}, cid, 401 + i)
        if i in (5, 9, 16):
            store.append("reaction.snapshot", {"counts": {"👍": 3, "🔍": 1},
                                               "complete_actor_list": False, "synthetic": True}, cid, 401 + i)
    store.append("membership.service", {"action": {"_": "MessageActionChatAddUser", "users": [70009]},
                                        "synthetic": True}, groups[0][0], 430, 70001)
    store.append("coverage.gap", {"reason": "Synthetic transport interruption",
                                 "completeness": "unknown", "synthetic": True})
    store.append("connection.restored", {"synthetic": True, "completeness": "unknown"})
