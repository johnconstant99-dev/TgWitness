from collections import Counter
from datetime import datetime, timedelta, timezone
import html
import math


CHARTS = (("activity", "Activity over time"), ("heatmap", "Weekly rhythm"),
          ("participants", "Activity by participant"), ("chats", "Activity by chat"),
          ("composition", "Record composition"))
LIMIT = 10000
MESSAGE_KINDS = ("message.new", "message.snapshot", "message.recovered")
KIND_LABELS = {"messages": "Message observations", "edits": "Edit observations", "deletions": "Deletion notices",
               "service": "Service messages", "other": "Other records", "rows": "Message rows"}
SCOPE_JOURNAL = "Journal charts count message observations at capture time in UTC. Repeat observations may refer to the same message. Edits and deletion notices are counted separately; they are not attributed to an editor or deleter."
SCOPE_SNAPSHOT = "Snapshot charts count the message rows included in this copy, using their recorded message time in UTC. They do not reconstruct activity outside the selected scope."
CAUTION = "Activity is not online presence. Sender identifiers do not establish a person's identity. Zero means no included observations, not proof that nothing happened."
UNKNOWN = "Unknown or withheld"
OTHER = "Other / unlisted"


def moment(value):
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def label(value):
    return str(value)[:160] if type(value) in (str, int) else ""


class Analytics:
    def __init__(self, basis="journal"):
        self.basis = basis
        self.total = self.messages = self.undated = self.date_overflow = 0
        self.days, self.people, self.chats, self.kinds = Counter(), Counter(), Counter(), Counter()
        self.people_names, self.chat_names = {}, {}
        self.heat = [[0] * 24 for _ in range(7)]
        self.first = self.last = None
        self.overflow = {"participants": 0, "chats": 0}

    def group(self, table, names, value, name, kind):
        key = label(value)
        if key and key not in table and len(table) >= LIMIT:
            self.overflow[kind] += 1
            return
        table[key] += 1
        if key and label(name):
            names[key] = label(name)

    def message(self, at, sender, name, chat, title):
        self.messages += 1
        self.group(self.people, self.people_names, sender, name, "participants")
        self.group(self.chats, self.chat_names, chat, title, "chats")
        time = moment(at)
        if time is None:
            self.undated += 1
            return
        self.first = min(self.first, time) if self.first else time
        self.last = max(self.last, time) if self.last else time
        self.heat[time.weekday()][time.hour] += 1
        day = time.date().isoformat()
        if day not in self.days and len(self.days) >= LIMIT:
            self.date_overflow += 1
        else:
            self.days[day] += 1

    def journal(self, event):
        self.total += 1
        kind = event.get("kind")
        payload = event.get("payload") or {}
        category = ("messages" if kind in MESSAGE_KINDS else "edits" if kind == "message.edited" else
                    "deletions" if kind == "message.deleted" else "other")
        self.kinds[category] += 1
        if category == "messages":
            observed = payload.get("sender_observation") or {}
            self.message(event.get("observed_at"), payload.get("sender_id"),
                         observed.get("display_name") if isinstance(observed, dict) else None,
                         event.get("chat_id"), payload.get("title"))

    def snapshot(self, row, chat=None):
        self.total += 1
        chat = chat or {}
        service = row.get("type") == "service" or bool(row.get("action"))
        self.kinds["service" if service else "rows"] += 1
        if not service:
            person = row.get("sender")
            name = (' '.join(label(person.get(key)) for key in ("first_name", "last_name")).strip()
                    or label(person.get("title"))) if isinstance(person, dict) else label(person)
            sender = row.get("from_id")
            if isinstance(sender, dict):
                sender = next((str(key) + ':' + str(sender[key]) for key in ("user_id", "channel_id", "chat_id") if type(sender.get(key)) is int), None)
            self.message(row.get("date"), sender, row.get("from") or name,
                         chat.get("id"), chat.get("title"))

    def result(self):
        series = []
        if self.first and self.last:
            start, end = self.first.date(), self.last.date()
            width = max(1, math.ceil(((end - start).days + 1) / 90))
            bins = Counter()
            for day, count in self.days.items():
                index = (datetime.fromisoformat(day).date() - start).days // width
                bins[index] += count
            for index in range((end - start).days // width + 1):
                low = start + timedelta(days=index * width)
                high = low + timedelta(days=min(width - 1, (end - low).days))
                series.append({"from": low.isoformat(), "to": high.isoformat(), "count": bins[index]})

        def groups(table, names):
            return [{"id": key or None, "label": names.get(key) or key or UNKNOWN, "count": count}
                    for key, count in sorted(table.items(), key=lambda item: (-item[1], item[0]))]

        return {"format": "tgwitness-report-analytics-v1", "basis": self.basis, "timezone": "UTC",
                "records": self.total, "messages": self.messages, "undated": self.undated,
                "first": self.first.isoformat() if self.first else None,
                "last": self.last.isoformat() if self.last else None,
                "activity": series, "heatmap": self.heat,
                "participants": groups(self.people, self.people_names), "chats": groups(self.chats, self.chat_names),
                "composition": [{"id": key, "label": KIND_LABELS[key], "count": count}
                                for key, count in sorted(self.kinds.items())],
                "unlisted": {**self.overflow, "activity": self.date_overflow},
                "method": SCOPE_JOURNAL if self.basis == "journal" else SCOPE_SNAPSHOT, "limitations": CAUTION}


def collect(rows, basis="journal", chat=None):
    measured = Analytics(basis)
    for row in rows:
        if basis == "journal":
            measured.journal(row)
        elif basis == "sharing":
            measured.snapshot(row.get("message") or {}, row.get("chat"))
        else:
            measured.snapshot(row, chat)
    return measured.result()


CONTROLS = {"activity": "activity_chart", "heatmap": "hourly_chart", "participants": "participant_chart",
            "chats": "chat_chart", "composition": "composition_chart"}


def selected(options):
    return [(key, title) for key, title in CHARTS if options.get(CONTROLS[key], True)]


def project(data, options):
    if data.get("projected"):
        return data
    output = {**data, "projected": True, "participant_labels": options.get("participant_labels", "aliases"),
              "sender_groups": sum(row.get("id") is not None for row in data["participants"])}
    people = data["participants"]
    aliases = {row["id"]: index for index, row in enumerate(sorted((row for row in people if row["id"] is not None), key=lambda row: str(row["id"])), 1)}
    output["participants"] = [{**row, "id": ("participant-%02d" % aliases[row["id"]]) if row["id"] is not None else None,
        "label": ("Participant %02d" % aliases[row["id"]]) if row["id"] is not None else UNKNOWN}
        if options.get("participant_labels", "aliases") == "aliases" else {**row, "label": str(row["id"]) if row["id"] is not None else UNKNOWN}
        for row in people]
    for key, control in CONTROLS.items():
        if not options.get(control, True):
            output.pop(key, None)
    return output


def ranking(data, key, top_n):
    known = [row for row in data[key] if row.get("id") is not None]
    rows = list(known[:top_n]) + [row for row in data[key] if row.get("id") is None]
    rest = sum(row["count"] for row in known[top_n:]) + data.get("unlisted", {}).get(key, 0)
    if rest:
        rows.append({"id": None, "label": OTHER, "count": rest})
    return rows


def e(value):
    return html.escape(str(value))


def svg_bars(rows, say, vertical=False):
    maximum = max((r["count"] for r in rows), default=0) or 1
    if vertical:
        step = 900 / max(1, len(rows))
        bars = ''.join('<rect class="chart-bar" x="%.2f" y="%.2f" width="%.2f" height="%.2f"><title>%s: %s</title></rect>' %
                       (i * step + 1, 160 - row["count"] / maximum * 150, max(.5, step - 2),
                        row["count"] / maximum * 150, e(row["label"]), row["count"]) for i, row in enumerate(rows))
        return ('<svg class="activity-svg" role="img" aria-label="' + e(say("Activity over time")) + '" viewBox="0 0 900 180">'
                '<path class="chart-gridline" d="M0 10H900 M0 85H900 M0 160H900"/>' + bars + '</svg>'
                '<div class="chart-axis"><span>' + e(rows[0]["label"] if rows else "—") + '</span><span>'
                + e(say("Maximum per interval")) + ': ' + str(maximum if rows else 0) + '</span><span>'
                + e(rows[-1]["label"] if rows else "—") + '</span></div>')
    parts = ['<div class="rank-chart">']
    for row in rows:
        name = say(row["label"]) if row["label"] in (UNKNOWN, OTHER, *KIND_LABELS.values()) else row["label"]
        suffix = ' · ' + str(row['id']) if row.get('id') and row['label'] != str(row['id']) and row['id'] not in KIND_LABELS and not str(row['id']).startswith('participant-') else ''
        parts.append('<div class="rank-row"><span class="rank-label" dir="auto">' + e(name + suffix) + '</span><strong>'
                     + str(row["count"]) + '</strong><svg aria-hidden="true" viewBox="0 0 800 10" preserveAspectRatio="none">'
                     '<rect class="chart-track" width="800" height="10" rx="3"/><rect class="chart-bar" width="'
                     + str(800 * row["count"] / maximum) + '" height="10" rx="3"/></svg></div>')
    return ''.join(parts) + '</div>'


def heatmap(data, say):
    names = [say(name) for name in ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")]
    maximum = max((n for day in data["heatmap"] for n in day), default=0) or 1
    parts = ['<div class="heatmap-scroll"><table class="activity-heatmap"><caption>' + e(say("UTC hour · message observations / rows")) + '</caption><thead><tr><th></th>']
    parts += ['<th scope="col">%02d</th>' % hour for hour in range(24)]
    parts.append('</tr></thead><tbody>')
    for day, counts in enumerate(data["heatmap"]):
        parts.append('<tr><th scope="row">' + e(names[day]) + '</th>')
        for hour, count in enumerate(counts):
            level = math.ceil(count / maximum * 4) if count else 0
            parts.append('<td data-intensity="%d" title="%s %02d:00 UTC: %d"><span>%d</span></td>' %
                         (level, e(names[day]), hour, count, count))
        parts.append('</tr>')
    peak = max((n for day in data["heatmap"] for n in day), default=0)
    return ''.join(parts) + '</tbody></table></div><p class="chart-note">' + e(say("Darker cells mean more included observations. Maximum per cell: {n}", n=peak)) + '</p>'


def html_section(data, options, say):
    if not data or not selected(options):
        return ""
    parts = ['<section id="analytics" class="report-analytics"><div class="analytics-heading"><div><p class="eyebrow">'
             + e(say("THE RECORD IN NUMBERS")) + '</p><h2>' + e(say("Activity & participants"))
             + '</h2></div><span class="analytics-basis">UTC · ' + e(say("Observed" if data["basis"] == "journal" else "Included"))
             + '</span></div><p class="analytics-method">' + e(say(data["method"])) + '</p><div class="analytics-kpis">']
    for value, title in ((data["records"], "Records analysed"), (data["messages"], "Message observations" if data["basis"] == "journal" else "Message rows"),
                         (data.get("sender_groups", len(data.get("participants", []))), "Listed sender identifiers"), (data["undated"], "Without a usable timestamp")):
        parts.append('<div><strong>' + str(value) + '</strong><span>' + e(say(title)) + '</span></div>')
    parts.append('</div><div class="analytics-grid">')
    for key, title in selected(options):
        parts.append('<article class="chart-card chart-' + key + '"><h3>' + e(say(title)) + '</h3>')
        if key == "heatmap":
            parts.append(heatmap(data, say))
        else:
            rows = ([{"label": r["from"] + (' / ' + r["to"] if r["from"] != r["to"] else ''), "count": r["count"]}
                     for r in data["activity"]] if key == "activity" else ranking(data, key, options.get("chart_limit", 10))
                    if key in ("participants", "chats") else data["composition"])
            if rows:
                parts.append(svg_bars(rows, say, key == "activity"))
                if key == "activity":
                    parts.append('<details class="chart-data"><summary>' + e(say("Exact chart values")) + '</summary><table><thead><tr><th>'
                                 + e(say("UTC interval")) + '</th><th>' + e(say("Count")) + '</th></tr></thead><tbody>'
                                 + ''.join('<tr><td>' + e(r["label"]) + '</td><td>' + str(r["count"]) + '</td></tr>' for r in rows) + '</tbody></table></details>')
            else:
                parts.append('<p class="chart-empty">' + e(say("No included data for this chart.")) + '</p>')
        if data.get("unlisted", {}).get(key):
            parts.append('<p class="chart-note">' + e(say("Category limit reached. Unlisted observations: {n}", n=data["unlisted"][key])) + '</p>')
        parts.append('</article>')
    parts.append('</div><p class="analytics-caution">' + e(say(CAUTION)) + '</p></section>')
    return ''.join(parts)


def pdf_section(lay, data, options):
    with lay.pdf.local_context():
        _pdf_section(lay, data, options)


def _pdf_section(lay, data, options):
    if not data or not selected(options):
        return
    say, pdf = lay.say, lay.pdf
    accent = lay.design.accent
    if pdf.get_y() > 45 and not getattr(lay, "composition_chapter", False):
        pdf.add_page()
    lay.section(say("Activity & participants"), say(data["method"]))
    lay.figures([(say("Records analysed"), data["records"]), (say("Message observations" if data["basis"] == "journal" else "Message rows"), data["messages"]),
                 (say("Without a usable timestamp"), data["undated"])])
    for key, title in selected(options):
        if key in ("participants", "chats", "composition"):
            count = len(ranking(data, key, options.get("chart_limit", 10))) if key != "composition" else len(data[key])
            lay.need(min(pdf.eph - 15, 22 + count * 13))
        else:
            lay.need(75)
        lay.heading(say(title))
        if key == "heatmap":
            lay.need(53)
            y = pdf.get_y() + 5
            step = (pdf.epw - 14) / 24
            peak = max((n for day in data["heatmap"] for n in day), default=0)
            maximum = peak or 1
            for day, counts in enumerate(data["heatmap"]):
                pdf.set_xy(pdf.l_margin, y + day * 5)
                pdf.line_text(say(("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")[day]), size=7, align="L")
                for hour, count in enumerate(counts):
                    ratio = .12 + .88 * count / maximum if count else .04
                    pdf.set_fill_color(*(round(255 + (c - 255) * ratio) for c in accent))
                    pdf.rect(pdf.l_margin + 14 + hour * step, y + day * 5, step - .6, 4.4, style="F")
            pdf.set_font("Sans", size=6)
            for hour in range(24):
                pdf.set_xy(pdf.l_margin + 14 + hour * step, y - 5)
                pdf.cell(step, 3, f"{hour:02d}", align="C")
            pdf.set_y(y + 38)
            lay.text(say("UTC hour · message observations / rows"), size=8)
            lay.text(say("Darker cells mean more included observations. Maximum per cell: {n}", n=peak), size=8)
        else:
            rows = ([{"label": r["from"] + (' / ' + r["to"] if r["from"] != r["to"] else ''), "count": r["count"]}
                     for r in data["activity"]] if key == "activity" else ranking(data, key, options.get("chart_limit", 10))
                    if key in ("participants", "chats") else data["composition"])
            maximum = max((r["count"] for r in rows), default=0) or 1
            if key == "activity" and rows:
                lay.need(49)
                y, step = pdf.get_y(), pdf.epw / len(rows)
                pdf.set_fill_color(*accent)
                for index, row in enumerate(rows):
                    height = row["count"] / maximum * 30
                    pdf.rect(pdf.l_margin + index * step, y + 30 - height, max(.3, step - .5), height, style="F")
                pdf.set_y(y + 33)
                lay.text(rows[0]["label"] + " — " + rows[-1]["label"] + " · UTC", size=8)
                lay.text(say("Maximum per interval") + ': ' + str(maximum), size=8)
            else:
                for row in rows:
                    lay.need(18)
                    name = say(row["label"]) if row["label"] in (UNKNOWN, OTHER, *KIND_LABELS.values()) else row["label"]
                    suffix = ' · ' + str(row['id']) if row.get('id') and row['label'] != str(row['id']) and row['id'] not in KIND_LABELS and not str(row['id']).startswith('participant-') else ''
                    lay.text(name + suffix + "   ·   " + str(row["count"]), size=8)
                    pdf.set_fill_color(*accent)
                    pdf.rect(pdf.l_margin, pdf.get_y(), pdf.epw * row["count"] / maximum, 2, style="F")
                    lay.gap(4)
            if not rows:
                lay.text(say("No included data for this chart."))
        if data.get("unlisted", {}).get(key):
            lay.text(say("Category limit reached. Unlisted observations: {n}", n=data["unlisted"][key]), size=8)
    lay.text(say(CAUTION), size=8)


def text_keys():
    import ast
    from pathlib import Path
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    return list(dict.fromkeys([node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "say" and node.args
        and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)]
        + [title for _, title in CHARTS] + list(KIND_LABELS.values()) + [SCOPE_JOURNAL, SCOPE_SNAPSHOT, CAUTION, UNKNOWN, OTHER,
        "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun", "Records analysed", "Listed sender identifiers",
        "Without a usable timestamp", "Observed", "Included"]))
