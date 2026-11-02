from html import escape


TITLE = "Selected data"
SCOPE_NOTE = ("The charts, message histories and transcript use this selection. Integrity, custody and coverage "
              "describe the complete source journal. The evidence ZIP keeps that journal and its attachments unchanged.")
GAP_NOTE = ("These message numbers were not observed in the source journal. They do not establish deletion. "
            "Known deleted messages and messages missing on recheck are separate observations.")
CONTEXT_NOTE = ("Gaps use the chosen chats and the message-number span observed during the chosen dates. "
                "Author and event filters do not create gaps. Neighboring saved messages are context and may be outside the selection.")
KINDS = {"message.new": "New message", "message.snapshot": "History snapshot",
         "message.recovered": "Recovered message", "message.edited": "Edits",
         "message.deleted": "Deletions", "message.missing_on_recheck": "Missing on recheck"}


def text_keys():
    return [TITLE, SCOPE_NOTE, GAP_NOTE, CONTEXT_NOTE, "Selected records", "Source journal records",
            "Observation dates (UTC)", "Selected authors", "All authors", "All dates", "Event types",
            "Unobserved message IDs", "Unobserved IDs: {ids} in {ranges} ranges.",
            "Showing {shown} of {total} ranges.", "Missing ID range", "Saved before", "Saved after",
            "No unobserved message IDs were found between the saved boundaries.",
            "No saved message", "Message {id} · record #{seq}", "Text was not recorded",
            "No records match this selection.", "All journal records", "Source journal coverage", "Selected message histories",
            "Saved versions matching the report filters; other versions remain in the source journal.",
            *KINDS.values()]


def scope_rows(material, say):
    selection, counts, source = material["selection"], material["counts"], material["source"]
    return [(say("Selected records"), str(counts["selected_records"])),
            (say("Source journal records"), str(source["records"])),
            (say("Chats"), ", ".join(map(str, selection["chats"])) or say("All chats")),
            (say("Selected authors"), ", ".join(map(str, selection["senders"])) or say("All authors")),
            (say("Observation dates (UTC)"), " — ".join((selection["date_from"] or "…", selection["date_to"] or "…"))
             if selection["date_from"] or selection["date_to"] else say("All dates")),
            (say("Event types"), ", ".join(say(KINDS[k]) for k in selection["kinds"]) if selection["enabled"] else say("All journal records"))]


def neighbor_text(item, say):
    if not item:
        return say("No saved message")
    return (say("Message {id} · record #{seq}", id=item["message_id"], seq=item["seq"])
            + "\n" + (item.get("text") or say("Text was not recorded")))


def html(material, say):
    if not material:
        return ""
    from .report import e, kv, section, table
    out = section("", "report-selection", say(TITLE), say(SCOPE_NOTE))
    out += kv([(label, e(value)) for label, value in scope_rows(material, say)])
    if not material["counts"]["selected_records"]:
        out += '<p class="lead">' + e(say("No records match this selection.")) + '</p>'
    gaps = material.get("id_gaps") or {}
    if gaps.get("enabled"):
        out += '<h3>' + e(say("Unobserved message IDs")) + '</h3><p>' + e(say(GAP_NOTE)) + '</p>'
        out += '<p>' + e(say(CONTEXT_NOTE)) + '</p>'
        out += '<p class="lead">' + e(say("Unobserved IDs: {ids} in {ranges} ranges.",
                                        ids=gaps["ids_total"], ranges=gaps["ranges_total"])) + '</p>'
        rows = gaps.get("rows") or []
        if rows:
            out += table([say("Chat"), say("Missing ID range"), say("Saved before"), say("Saved after")],
                         [[e(row["chat_id"]), e(str(row["start"]) + '–' + str(row["end"])),
                           escape(neighbor_text(row.get("before"), say)).replace('\n', '<br>'),
                           escape(neighbor_text(row.get("after"), say)).replace('\n', '<br>')]
                          for row in rows])
        else:
            out += '<p>' + e(say("No unobserved message IDs were found between the saved boundaries.")) + '</p>'
        if gaps.get("truncated"):
            out += '<p>' + e(say("Showing {shown} of {total} ranges.", shown=len(rows), total=gaps["ranges_total"])) + '</p>'
    return out + '</section>'


def pdf(lay, material):
    if not material:
        return
    say = lay.say
    lay.section(say(TITLE), say(SCOPE_NOTE))
    lay.kv(scope_rows(material, say))
    if not material["counts"]["selected_records"]:
        lay.text(say("No records match this selection."))
    gaps = material.get("id_gaps") or {}
    if not gaps.get("enabled"):
        return
    lay.heading(say("Unobserved message IDs"))
    lay.text(say(GAP_NOTE), size=9)
    lay.text(say(CONTEXT_NOTE), size=9)
    lay.text(say("Unobserved IDs: {ids} in {ranges} ranges.", ids=gaps["ids_total"], ranges=gaps["ranges_total"]))
    rows = gaps.get("rows") or []
    if rows:
        lay.grid([say("Chat"), say("Missing ID range"), say("Saved before"), say("Saved after")],
                 [[str(row["chat_id"]), str(row["start"]) + '–' + str(row["end"]),
                   neighbor_text(row.get("before"), say), neighbor_text(row.get("after"), say)] for row in rows],
                 (14, 16, 35, 35))
    else:
        lay.text(say("No unobserved message IDs were found between the saved boundaries."))
    if gaps.get("truncated"):
        lay.text(say("Showing {shown} of {total} ranges.", shown=len(rows), total=gaps["ranges_total"]))
