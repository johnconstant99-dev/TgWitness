import html
import math
from array import array
from datetime import datetime, timezone

DAY, WEEK = 86400, 7 * 86400
STEPS = (3600, 6 * 3600, DAY, WEEK, 30 * DAY, 91 * DAY, 365 * DAY)
COLUMNS = 60
TOP_ROWS = 25
TOP_SENDERS = 12
YEARS = 6
GAPS_SHOWN = 300
WEEK_ORIGIN = 4 * DAY
DAY_WINDOW, HOUR_WINDOW = 2 * DAY, 3 * 3600
DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
CONFIDENCE = {"proven": "proven by a reply or pin", "high": "high confidence", "medium": "medium confidence",
              "low": "low confidence"}
SCOPE_REASONS = {"chat_kinds": "some chat kinds were not selected", "chat_ids": "only listed chats were selected",
                 "archived_excluded": "archived chats were excluded", "sender_filter": "a sender filter was applied",
                 "text_filter": "a text filter was applied", "own_messages_only": "only own messages were kept",
                 "unselected_chats": "some private chats or groups were not selected",
                 "inventory_incomplete": "the chat list was incomplete"}
CSS = """
.activity-map{--map-accent:var(--chart-accent,var(--accent,#235dcc));--map-loss:#d9480f;--map-empty:var(--line,#dce2eb);--map-paper:var(--card,var(--paper,#fff))}
@media(prefers-color-scheme:dark){.activity-map{--map-loss:#ff8a4c}}
.activity-map .map-card{padding:20px 22px;border:1px solid var(--line);background:var(--map-paper);border-radius:12px;margin:18px 0;break-inside:avoid}
.activity-map h3{font:600 15px/1.4 system-ui,sans-serif;margin:0 0 6px}.activity-map .map-note{font-size:12px;color:var(--muted);margin:4px 0 14px;max-width:90ch}
.map-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:18px 0}.map-kpis div{padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--map-paper);min-width:0}
.map-kpis strong{display:block;font-size:22px;line-height:1.3;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}.map-kpis strong.small{font-size:15px;line-height:1.5}.map-kpis span{font-size:12px;color:var(--muted)}
.map-scroll{overflow-x:auto;direction:ltr;padding-bottom:4px}.map-grid{border-collapse:separate;border-spacing:3px}
.map-grid caption{text-align:start;font:600 12px/1.6 system-ui,sans-serif;color:var(--muted);padding-bottom:4px}
.map-grid th{font:500 10px/1.3 system-ui,sans-serif;color:var(--muted);text-align:start;white-space:nowrap;overflow:hidden;border:0!important;padding:0 4px 0 0!important;background:transparent!important}
.map-grid td{width:15px;min-width:15px;height:15px;padding:0!important;border:0!important;border-radius:3px;background:var(--map-empty);position:relative}
.map-grid td.blank{background:transparent}.map-grid td[data-a="1"]{background:color-mix(in srgb,var(--map-accent) 25%,var(--map-paper))}
.map-grid td[data-a="2"]{background:color-mix(in srgb,var(--map-accent) 48%,var(--map-paper))}.map-grid td[data-a="3"]{background:color-mix(in srgb,var(--map-accent) 72%,var(--map-paper))}
.map-grid td[data-a="4"]{background:var(--map-accent)}
.map-grid td[data-l]::after{content:"";position:absolute;left:50%;top:50%;width:6px;height:6px;transform:translate(-50%,-50%);border-radius:50%;background:var(--map-loss);box-shadow:0 0 0 1.5px var(--map-paper)}
.map-grid td[data-l="1"]::after{width:4px;height:4px}.map-grid td[data-l="3"]::after{width:8px;height:8px}.map-grid td[data-l="4"]::after{width:10px;height:10px}
.map-lanes{width:100%;table-layout:fixed}.map-lanes col.lane-col{width:170px}.map-lanes col.total-col{width:156px}.map-lanes td{width:auto;min-width:0;height:16px}
.map-lanes th.lane{overflow:hidden;text-overflow:ellipsis;font-size:12px;color:var(--ink)}.map-lanes td.total{background:transparent;font:500 10px/1.2 ui-monospace,monospace;color:var(--muted);text-align:end;padding-inline-start:6px!important;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.map-lanes tr.outside th.lane{color:var(--map-loss);font-style:italic}.map-week{width:100%;table-layout:fixed}.map-week td{width:auto;min-width:0;height:20px}.map-week th[scope=row]{width:42px;overflow:visible}
.map-legend{display:flex;flex-wrap:wrap;align-items:center;gap:6px 16px;font-size:11px;color:var(--muted);margin-top:12px}
.map-legend i{display:inline-block;width:11px;height:11px;border-radius:3px;background:var(--map-empty);vertical-align:-1px;margin-inline-end:5px}.map-legend i[data-a="2"]{background:color-mix(in srgb,var(--map-accent) 48%,var(--map-paper))}
.map-legend i[data-a="4"]{background:var(--map-accent)}.map-legend i.loss{width:8px;height:8px;border-radius:50%;background:var(--map-loss)}
.map-pair{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.map-pair .map-card{margin:0}
.map-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}.map-table th,.map-table td{padding:7px 8px;border-bottom:1px solid var(--line);text-align:start;vertical-align:top}
.map-table td.num,.map-table th.num{text-align:end;font-variant-numeric:tabular-nums;white-space:nowrap}.map-badge{display:inline-block;padding:1px 8px;border-radius:9px;font-size:11px;border:1px solid var(--line);margin-inline-start:4px}
.map-badge.proven,.map-badge.high{border-color:var(--map-loss);color:var(--map-loss)}.gap-mark{margin:10px 0;padding:9px 14px;border:1px dashed var(--map-loss,#d9480f);border-radius:8px;font-size:13px;color:var(--ink)}
.gap-mark b{color:var(--map-loss,#d9480f)}.gap-mark small{display:block;color:var(--muted)}
@media(max-width:720px){.map-pair{grid-template-columns:1fr}.map-lanes col.lane-col{width:110px}.map-lanes col.total-col{width:0}.map-lanes td.total{display:none}}
@media print{.map-grid td,.map-grid td::after,.map-legend i{print-color-adjust:exact;-webkit-print-color-adjust:exact}.map-scroll{overflow:visible}}
"""


def e(value):
    return html.escape("" if value is None else str(value), quote=True)


def seconds(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return None if parsed.tzinfo is None else int(parsed.timestamp())


def day_text(value):
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d")


def time_text(value):
    if type(value) is not int or value < 0:
        return "—"
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def level(value, peak):
    if value <= 0 or peak <= 0:
        return 0
    return 1 + min(3, int(math.log1p(value) / math.log1p(peak) * 3.999))


def number(value):
    if isinstance(value, float):
        return ("%.1f" % value).rstrip("0").rstrip(".") if value < 10 else str(round(value))
    return str(value)


class ActivityMap:
    def __init__(self):
        self.times, self.senders, self.kinds = {}, {}, {}

    def add(self, chat_id, kind, row):
        at = seconds(row.get("date"))
        if type(chat_id) is not int or at is None:
            return
        sender = row.get("from_id")
        self.kinds.setdefault(chat_id, kind)
        self.times.setdefault(chat_id, array("q")).append(at)
        self.senders.setdefault(chat_id, array("q")).append(sender if type(sender) is int else 0)

    def span(self, chats=None):
        values = [(min(t), max(t)) for chat, t in self.times.items() if t and (chats is None or chat in chats)]
        return (min(v[0] for v in values), max(v[1] for v in values)) if values else (None, None)


def absences(gaps, chat=None):
    if not isinstance(gaps, dict):
        return
    for gap in gaps["shared"]["gaps"]:
        start, end = gap["after"][2], gap["before"][2]
        start, end = (end, end) if start < 0 else (start, start) if end < 0 else (start, end)
        for item in gap["proven"]:
            if chat is None or item[1] == chat:
                yield item[1], start, end, 1.0, "proven"
        rest = gap["count"] - len(gap["proven"])
        if rest <= 0:
            continue
        for owner, share in gap["likely"]:
            if chat is None or owner == chat:
                yield owner, start, end, rest * share, gap["confidence"]
        if chat is None and gap["other"]:
            yield None, start, end, rest * gap["other"], gap["confidence"]
    for item in gaps["chats"]:
        if chat is not None and item["chat"] != chat:
            continue
        for low, high, start, end in item["ranges"]:
            yield item["chat"], min(start, end), max(start, end), float(high - low + 1), "certain"


def spread(amount, start, end, origin, step, count):
    if count <= 0 or amount <= 0:
        return
    first, last = (start - origin) // step, (end - origin) // step
    first, last = max(0, min(count - 1, first)), max(0, min(count - 1, last))
    if end <= start or first == last:
        yield first, amount
        return
    width = end - start
    for index in range(first, last + 1):
        low, high = max(start, origin + index * step), min(end, origin + (index + 1) * step)
        if high > low:
            yield index, amount * (high - low) / width


def grid(start, end):
    for step in STEPS:
        origin = (start - WEEK_ORIGIN) // step * step + WEEK_ORIGIN if step == WEEK else start // step * step
        count = (end - origin) // step + 1
        if count <= COLUMNS:
            return origin, step, count
    origin = start // STEPS[-1] * STEPS[-1]
    return origin, STEPS[-1], (end - origin) // STEPS[-1] + 1


def bin_label(origin, step, index):
    at = datetime.fromtimestamp(origin + index * step, timezone.utc)
    return at.strftime("%Y-%m-%d %H:00") if step < DAY else at.strftime("%Y-%m-%d")


def profile(series):
    days, counts, total = {}, [[0] * 24 for _ in range(7)], 0
    for times in series:
        for at in times:
            day = at // DAY
            days[day] = days.get(day, 0) + 1
            counts[(day + 3) % 7][at % DAY // 3600] += 1
            total += 1
    return days, counts, total


def absent_profile(absent):
    days, losses = {}, [[0.0] * 24 for _ in range(7)]
    for _, start, end, amount, _ in absent:
        if end - start > DAY_WINDOW:
            continue
        origin = start // DAY * DAY
        for index, part in spread(amount, start, end, origin, DAY, (end - origin) // DAY + 1):
            days[start // DAY + index] = days.get(start // DAY + index, 0.0) + part
        if end - start > HOUR_WINDOW:
            continue
        hours = (end - start) // 3600 + 1
        origin = start // 3600 * 3600
        for index, part in spread(amount, start, end, origin, 3600, hours):
            moment = origin + index * 3600
            losses[(moment // DAY + 3) % 7][moment % DAY // 3600] += part
    return days, losses


def loss_level(value, peak):
    if peak <= 0 or value < max(0.05, peak * 0.05):
        return 0
    return 1 + min(3, int(value / peak * 3.999))


def legend(say, loss=True):
    parts = ['<div class="map-legend"><span><i></i>' + e(say("No messages")) + '</span><span><i data-a="2"></i>'
             + e(say("Fewer messages")) + '</span><span><i data-a="4"></i>' + e(say("More messages")) + '</span>']
    if loss:
        parts.append('<span><i class="loss"></i>' + e(say("Absent message numbers (larger dot, more)")) + '</span>')
    return ''.join(parts) + '</div>'


def cell(count, peak, lost, loss_peak, tip):
    attributes = ' data-a="%d"' % level(count, peak)
    mark = loss_level(lost, loss_peak)
    if mark:
        attributes += ' data-l="%d"' % mark
    return '<td' + attributes + ' title="' + e(tip) + '"></td>'


def calendar(days, losses, say):
    active = [day for day, value in days.items() if value] + [day for day, value in losses.items() if value >= 0.05]
    if not active:
        return ""
    low, high = min(active), max(active)
    years = list(range(datetime.fromtimestamp(low * DAY, timezone.utc).year,
                       datetime.fromtimestamp(high * DAY, timezone.utc).year + 1))
    shown, hidden = years[-YEARS:], years[:-YEARS]
    peak, loss_peak = max(days.values(), default=0), max(losses.values(), default=0.0)
    parts = ['<div class="map-card"><h3>' + e(say("Calendar")) + '</h3><p class="map-note">'
             + e(say("Each square is one UTC day; rows are weekdays. Darker means more messages. A dot marks absent message numbers whose neighbouring messages are at most two days apart; the tables list the rest.")) + '</p>']
    for year in reversed(shown):
        first = max(low, int(datetime(year, 1, 1, tzinfo=timezone.utc).timestamp()) // DAY)
        last = min(high, int(datetime(year, 12, 31, tzinfo=timezone.utc).timestamp()) // DAY)
        start = first - (first - 4) % 7
        weeks = (last - start) // 7 + 1
        months, previous = [], None
        for index in range(weeks):
            month = datetime.fromtimestamp(max(start + index * 7, first) * DAY, timezone.utc).month
            if month != previous:
                months.append([month, 1])
                previous = month
            else:
                months[-1][1] += 1
        header = '<tr><th></th>' + ''.join('<th scope="colgroup" colspan="%d">%s</th>' % (
            span, e(say(MONTH_NAMES[month - 1])) if span > 1 else "") for month, span in months) + '</tr>'
        rows = []
        for weekday in range(7):
            cells = ['<th scope="row">' + (e(say(DAY_NAMES[weekday])) if weekday % 2 == 0 else "") + '</th>']
            for index in range(weeks):
                day = start + index * 7 + weekday
                if day < first or day > last:
                    cells.append('<td class="blank"></td>')
                    continue
                count, lost = days.get(day, 0), losses.get(day, 0.0)
                tip = day_text(day * DAY) + ": " + say("{n} messages", n=count)
                if loss_level(lost, loss_peak):
                    tip += " · " + say("absent: {n}", n=number(lost))
                cells.append(cell(count, peak, lost, loss_peak, tip))
            rows.append('<tr>' + ''.join(cells) + '</tr>')
        total = sum(value for day, value in days.items() if first <= day <= last)
        parts.append('<div class="map-scroll"><table class="map-grid map-calendar"><caption>' + str(year) + ' · '
                     + e(say("{n} messages", n=total)) + '</caption><thead>' + header + '</thead><tbody>' + ''.join(rows)
                     + '</tbody></table></div>')
    if hidden:
        parts.append('<p class="map-note">' + e(say("Earlier years with messages: {years}", years=", ".join(map(str, hidden)))) + '</p>')
    return ''.join(parts) + legend(say) + '</div>'


def lanes(rows, origin, step, count, say, title, note):
    if not rows:
        return ""
    peak = max((value for row in rows for value in row["counts"]), default=0)
    loss_peak = max((value for row in rows for value in row["losses"]), default=0.0)
    segment = max(1, -(-count // 6))
    header = '<tr><th></th>' + ''.join('<th scope="colgroup" colspan="%d">%s</th>' % (
        min(segment, count - index), e(bin_label(origin, step, index)[:10])) for index in range(0, count, segment)) + '<th></th></tr>'
    body = []
    for row in rows:
        cells = ['<th scope="row" class="lane" dir="auto" title="' + e(row["label"]) + '">'
                 + (('<a href="' + e(row["link"]) + '">' + e(row["label"]) + '</a>') if row.get("link") else e(row["label"])) + '</th>']
        for index in range(count):
            value, lost = row["counts"][index], row["losses"][index]
            tip = bin_label(origin, step, index) + " · " + say("{n} messages", n=value)
            if loss_level(lost, loss_peak):
                tip += " · " + say("absent: {n}", n=number(lost))
            cells.append(cell(value, peak, lost, loss_peak, tip))
        cells.append('<td class="total">' + e(row["total"]) + '</td>')
        body.append('<tr' + (' class="outside"' if row.get("outside") else '') + '>' + ''.join(cells) + '</tr>')
    columns = '<colgroup><col class="lane-col">' + '<col>' * count + '<col class="total-col"></colgroup>'
    return ('<div class="map-card"><h3>' + e(title) + '</h3><p class="map-note">' + e(note) + '</p><div class="map-scroll">'
            '<table class="map-grid map-lanes">' + columns + '<thead>' + header + '</thead><tbody>' + ''.join(body)
            + '</tbody></table></div>' + legend(say) + '</div>')


def week(matrix, say, title, loss=False):
    peak = max((value for day in matrix for value in day), default=0)
    if not peak:
        return ""
    note = ('<p class="map-note">' + e(say("Only absent numbers whose neighbouring messages are at most three hours apart.")) + '</p>') if loss else ''
    head = '<tr><th></th>' + ''.join('<th scope="col">%s</th>' % ('%02d' % hour if hour % 3 == 0 else '')
                                     for hour in range(24)) + '</tr>'
    rows = []
    for index, values in enumerate(matrix):
        cells = ['<th scope="row">' + e(say(DAY_NAMES[index])) + '</th>']
        for hour, value in enumerate(values):
            tip = say(DAY_NAMES[index]) + ' %02d:00 UTC · ' % hour + number(value)
            cells.append(cell(0, 1, value, peak, tip) if loss else cell(value, peak, 0, 0, tip))
        rows.append('<tr>' + ''.join(cells) + '</tr>')
    return ('<div class="map-card"><h3>' + e(title) + '</h3>' + note + '<div class="map-scroll"><table class="map-grid map-week">'
            '<thead>' + head + '</thead><tbody>' + ''.join(rows) + '</tbody></table></div>' + legend(say, loss) + '</div>')


def lane_rows(groups, absent, origin, step, count, say):
    rows = []
    for key, label, link, times, outside in groups:
        counts, losses = [0] * count, [0.0] * count
        for at in times:
            counts[min(count - 1, max(0, (at - origin) // step))] += 1
        for owner, start, end, amount, _ in absent:
            if owner == key or outside and owner is None:
                for index, part in spread(amount, start, end, origin, step, count):
                    losses[index] += part
        lost = sum(losses)
        total = say("{n} msgs", n=len(times)) + (" · " + say("absent {n}", n=number(lost)) if lost >= 0.05 else "")
        rows.append({"label": label, "link": link, "counts": counts, "losses": losses, "total": total, "outside": outside})
    return rows


def kpis(items):
    return '<div class="map-kpis">' + ''.join('<div><strong' + (' class="small"' if len(str(value)) > 12 else '') + '>'
                                              + e(value) + '</strong><span>' + e(label) + '</span></div>' for value, label in items) + '</div>'


def account_map(activity, gaps, chats, say):
    titles = {chat["id"]: chat.get("title") or str(chat["id"]) for chat in chats if type(chat.get("id")) is int}
    start, end = activity.span()
    absent = list(absences(gaps))
    days, counts, total = profile(activity.times.values())
    lost_days, losses = absent_profile(absent)
    owners = {}
    for owner, _, _, amount, _ in absent:
        owners[owner] = owners.get(owner, 0.0) + amount
    shared = gaps["shared"] if isinstance(gaps, dict) else None
    lost_total = (shared["absent"] if shared else 0) + sum(item["absent"] for item in (gaps or {}).get("chats", []))
    parts = ['<section class="activity-map" id="activity-map"><h2>' + e(say("Activity and absent message numbers")) + '</h2>',
             '<p class="map-note">' + e(say("Message dates come from Telegram and are shown in UTC. Absent numbers are messages this export does not hold: deleted, hidden from this account or left out by the selection.")) + '</p>']
    parts.append(kpis([(total, say("Messages")), (len(activity.times), say("Chats with messages")), (len(days), say("Active days")),
                       (day_text(start) + " → " + day_text(end) if start is not None else "—", say("First and last message")),
                       (lost_total, say("Absent message numbers")),
                       (shared["proven"] if shared else 0, say("Proven by a reply or pin"))]))
    parts.append(calendar(days, lost_days, say))
    if start is not None:
        origin, step, count = grid(start, end)
        ranked = sorted(activity.times, key=lambda chat: (-owners.get(chat, 0.0), -len(activity.times[chat]), chat))
        groups = [(chat, titles.get(chat, str(chat)), "chats/" + str(chat) + ".html", activity.times[chat], False)
                  for chat in ranked[:TOP_ROWS]]
        if owners.get(None):
            groups.append((None, say("Chats not in this export"), None, (), True))
        parts.append(lanes(lane_rows(groups, absent, origin, step, count, say), origin, step, count, say,
                           say("Chats over time"), say("The {n} chats with the most absent numbers and messages; each column is one interval of the period.", n=len(groups))))
    pair = week(counts, say, say("Messages by weekday and hour")) + week(losses, say, say("Absent numbers by weekday and hour"), loss=True)
    if pair:
        parts.append('<div class="map-pair">' + pair + '</div>')
    if isinstance(gaps, dict):
        parts.append(gap_details(gaps, titles, say))
    return ''.join(parts) + '</section>'


def chat_title(chat, titles, say):
    if chat is None:
        return say("A chat not in this export")
    return titles.get(chat) or say("Chat {id} (not in this export)", id=chat)


def gap_details(gaps, titles, say):
    shared, parts = gaps["shared"], []
    scope = gaps["scope"]
    if not scope.get("complete"):
        parts.append('<p class="notice">' + e(say("The export was limited, so absent numbers also include messages outside the selection: {reasons}.",
                                                   reasons="; ".join(say(SCOPE_REASONS.get(r, r)) for r in scope.get("reasons", ())))) + '</p>')
    if shared["messages"]:
        parts.append('<div class="map-card"><h3>' + e(say("Private chats, bots and basic groups")) + '</h3><p class="map-note">'
                     + e(say("These chats share one message number sequence for the whole account. A missing number between two exported messages was a message of some chat. Its chat is proven when an exported reply or pin points at it; otherwise it is estimated from which chats were active between the neighbouring messages. The rest goes to chats not in this export.")) + '</p>')
        parts.append(kpis([(shared["absent"], say("Absent numbers")), (shared["runs"], say("Runs")),
                           (shared["proven"], say("Proven by a reply or pin")),
                           (sum(1 for g in shared["gaps"] if g["confidence"] == "high"), say("Runs attributed with high confidence")),
                           (number(shared["not_in_export"]["expected"]), say("Likely in chats not in this export")),
                           (shared["below_first"], say("Numbers below the oldest exported message"))]))
        rows = sorted((item for item in shared["by_chat"] if item[2] or item[3] >= 0.05), key=lambda item: (-(item[2] + item[3]), item[0]))
        if rows:
            parts.append('<table class="map-table"><thead><tr><th>' + e(say("Chat")) + '</th><th class="num">' + e(say("Messages"))
                         + '</th><th class="num">' + e(say("Proven absent")) + '</th><th class="num">' + e(say("Likely absent"))
                         + '</th><th class="num">' + e(say("Runs with high confidence")) + '</th></tr></thead><tbody>')
            for chat, messages, proven, expected, high in rows[:200]:
                link = ('<a href="chats/' + str(chat) + '.html" dir="auto">' + e(chat_title(chat, titles, say)) + '</a>') if messages else e(chat_title(chat, titles, say))
                parts.append('<tr><td>' + link + '</td><td class="num">' + str(messages) + '</td><td class="num">' + str(proven)
                             + '</td><td class="num">' + number(expected) + '</td><td class="num">' + str(high) + '</td></tr>')
            parts.append('</tbody></table>')
        if shared["gaps"]:
            ordered = sorted(shared["gaps"], key=lambda g: (-g["count"], g["from"]))[:GAPS_SHOWN]
            parts.append('<h3>' + e(say("Largest runs of absent numbers")) + '</h3><table class="map-table"><thead><tr><th>'
                         + e(say("Numbers")) + '</th><th>' + e(say("Between")) + '</th><th>' + e(say("Neighbours")) + '</th><th>'
                         + e(say("Most likely chat")) + '</th></tr></thead><tbody>')
            for gap in ordered:
                numbers = str(gap["from"]) + ("" if gap["from"] == gap["to"] else "–" + str(gap["to"])) + " (" + str(gap["count"]) + ")"
                neighbours = chat_title(gap["after"][1], titles, say) + " → " + chat_title(gap["before"][1], titles, say)
                likely = chat_title(gap["top"], titles, say)
                share = max([s for c, s in gap["likely"] if c == gap["top"]] or [gap["other"]])
                badge = '<span class="map-badge ' + e(gap["confidence"]) + '">' + e(say(CONFIDENCE[gap["confidence"]])) + '</span>'
                proven = ''.join('<br><small>' + e(say("No. {id}: chat {chat}, answered by message {source}", id=item[0],
                                 chat=chat_title(item[1], titles, say), source=item[3])) + '</small>' for item in gap["proven"][:5])
                parts.append('<tr><td class="num">' + e(numbers) + '</td><td>' + e(time_text(gap["after"][2])) + '<br>' + e(time_text(gap["before"][2]))
                             + '</td><td dir="auto">' + e(neighbours) + '</td><td dir="auto">' + e(likely) + ' · ' + str(round(share * 100))
                             + '% ' + badge + proven + '</td></tr>')
            parts.append('</tbody></table>')
            if len(shared["gaps"]) > GAPS_SHOWN:
                parts.append('<p class="map-note">' + e(say("message-gaps.json lists all runs, {n} more than shown here.", n=len(shared["gaps"]) - GAPS_SHOWN)) + '</p>')
        anomalies = shared["conflicts"]["count"] + shared["time_inversions"]["count"]
        if anomalies:
            parts.append('<p class="notice">' + e(say("Number sequence anomalies: {conflicts} numbers claimed by two chats, {inversions} messages dated earlier than a lower number. Telegram assigns these numbers in order, so check how these records were produced.",
                                                       conflicts=shared["conflicts"]["count"], inversions=shared["time_inversions"]["count"])) + '</p>')
        parts.append('</div>')
    numbered = [item for item in gaps["chats"]]
    if numbered:
        parts.append('<div class="map-card"><h3>' + e(say("Channels and supergroups")) + '</h3><p class="map-note">'
                     + e(say("Each of these chats numbers its own messages, so every missing number between the first and last exported message is a message of that chat.")) + '</p>'
                     '<table class="map-table"><thead><tr><th>' + e(say("Chat")) + '</th><th class="num">' + e(say("Numbers"))
                     + '</th><th class="num">' + e(say("Messages")) + '</th><th class="num">' + e(say("Absent numbers"))
                     + '</th><th class="num">' + e(say("Runs")) + '</th></tr></thead><tbody>')
        for item in sorted(numbered, key=lambda i: (-i["absent"], i["chat"])):
            parts.append('<tr><td><a href="chats/' + str(item["chat"]) + '.html" dir="auto">' + e(titles.get(item["chat"], str(item["chat"])))
                         + '</a></td><td class="num">' + str(item["first"]) + "–" + str(item["last"]) + '</td><td class="num">' + str(item["present"])
                         + '</td><td class="num">' + str(item["absent"]) + '</td><td class="num">' + str(len(item["ranges"])) + '</td></tr>')
        parts.append('</tbody></table></div>')
    parts.append('<p class="map-note">' + e(say("Method: kernel bandwidth {minutes} minutes, up to {n} neighbouring messages on each side; message-gaps.json holds every run and verify.py recomputes it from the signed pages.",
                                                minutes=gaps["method"]["bandwidth_seconds"] // 60, n=gaps["method"]["neighbors"])) + '</p>')
    return ''.join(parts)


def chat_map(activity, gaps, chat, say):
    times = activity.times.get(chat["id"], array("q"))
    absent = list(absences(gaps, chat["id"]))
    if not times and not absent:
        return ""
    days, counts, total = profile((times,))
    lost_days, losses = absent_profile(absent)
    parts = ['<section class="activity-map" id="activity-map"><h2>' + e(say("Activity in this chat")) + '</h2>']
    parts.append(kpis([(total, say("Messages")), (len(days), say("Active days")),
                       (number(sum(amount for *_, amount, _ in absent)), say("Absent message numbers"))]))
    parts.append(calendar(days, lost_days, say))
    senders = activity.senders.get(chat["id"], array("q"))
    if times and chat.get("kind") in ("group", "supergroup") and len(set(senders)) > 1:
        origin, step, count = grid(min(times), max(times))
        totals = {}
        for sender in senders:
            totals[sender] = totals.get(sender, 0) + 1
        top = sorted(totals, key=lambda s: (-totals[s], s))[:TOP_SENDERS]
        groups = [(("sender", sender), say("Sender {id}", id=sender) if sender else say("Sender not recorded"), None,
                   [at for at, who in zip(times, senders) if who == sender], False) for sender in top]
        parts.append(lanes(lane_rows(groups, [], origin, step, count, say), origin, step, count, say, say("Participants over time"),
                           say("The {n} most active senders by Telegram ID; each column is one interval.", n=len(top))))
    parts.append(week(losses, say, say("Absent numbers by weekday and hour"), loss=True))
    return ''.join(parts) + '</section>'


def markers(gaps, chat_id, kind):
    found = []
    if not isinstance(gaps, dict):
        return found
    if kind in ("supergroup", "channel"):
        for item in gaps["chats"]:
            if item["chat"] == chat_id:
                found += [(low, high, "certain", float(high - low + 1), start, end, ()) for low, high, start, end in item["ranges"]]
    else:
        for gap in gaps["shared"]["gaps"]:
            proven = [item for item in gap["proven"] if item[1] == chat_id]
            share = next((s for c, s in gap["likely"] if c == chat_id), 0.0)
            rest = gap["count"] - len(gap["proven"])
            if proven or gap["top"] == chat_id and rest:
                found.append((gap["from"], gap["to"], "proven" if proven and not (gap["top"] == chat_id and rest) else gap["confidence"],
                              (rest * share if gap["top"] == chat_id else 0.0) + len(proven), gap["after"][2], gap["before"][2], proven))
    return sorted(found)


def marker_html(marker, say):
    low, high, kind, amount, start, end, proven = marker
    numbers = str(low) + ("" if low == high else "–" + str(high))
    if kind == "certain":
        text = say("{n} message numbers are absent here ({numbers}): deleted before the export or not visible to this account.",
                   n=high - low + 1, numbers=numbers)
    elif kind == "proven":
        text = say("A message is absent here: number {numbers} belongs to this chat because an exported reply or pin points at it.", numbers=numbers)
    else:
        text = say("About {n} message(s) likely absent here: message numbers {numbers} ({confidence}).", n=number(amount), numbers=numbers,
                   confidence=say(CONFIDENCE[kind]))
    detail = say("Between {start} and {end}.", start=time_text(start), end=time_text(end))
    return ('<div class="gap-mark" data-gap="' + e(numbers) + '"><b>' + e(say("Absent")) + '</b> · ' + e(text)
            + '<small>' + e(detail) + '</small></div>')


class MarkerPlacer:
    def __init__(self, found):
        self.pending = sorted(found)

    def before(self, current):
        found = []
        while self.pending and type(current) is int and self.pending[-1][0] > current:
            found.append(self.pending.pop())
        return found

    def rest(self):
        found, self.pending = self.pending[::-1], []
        return found


def text_keys():
    import ast
    from pathlib import Path
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    keys = [node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "say" and node.args
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)]
    return list(dict.fromkeys(keys + list(DAY_NAMES) + list(MONTH_NAMES) + list(CONFIDENCE.values()) + list(SCOPE_REASONS.values())))
