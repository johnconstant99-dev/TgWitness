from datetime import datetime, timedelta, timezone


def seed_demo(store):
    if store.stats()["total"]:
        return
    store.set_setting("demo", True)
    groups = [(-100100001, "Northstar · Research", "supergroup"),
              (-100100002, "Harbor · Community", "supergroup"),
              (-100100003, "Signal · Announcements", "channel")]
    for cid, title, kind in groups:
        store.set_target(cid, title, kind, True)
    store.append("demo.created", {"synthetic": True, "meaning": "Fictional demonstration; no Telegram connection"})
    texts = [
        "Review notes are ready. Please keep all source references with the timeline.",
        "The next community briefing starts at 16:00 UTC.",
        "Reference archive: batch 042. We will publish the checksum after review.",
        "Draft status: waiting for the second reviewer.",
        "Meeting notes have been attached to the investigation.",
        "The date in the previous announcement needs a correction.",
    ]
    now = datetime.now(timezone.utc)
    for i in range(18):
        cid, _, _ = groups[i % 3]
        source = (now - timedelta(minutes=90 - i * 4)).isoformat()
        text = texts[i % len(texts)]
        store.append("message.new", {"text": text, "sender_id": 70001 + i % 4,
                                    "source": "synthetic_demo", "synthetic": True,
                                    "sent_at": source, "has_media": False},
                     cid, 401 + i, 70001 + i % 4, source)
        if i in (2, 7, 12):
            store.append("message.edited", {"text": text.replace("16:00", "17:30") + " Updated after review.",
                                           "sender_id": 70001 + i % 4, "editor_id": None,
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
