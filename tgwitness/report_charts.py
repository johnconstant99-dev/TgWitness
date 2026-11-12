from datetime import date
from html import escape
import math

TITLE = "Activity and participants"
INTRO = "Counts describe observations in this journal, not unique messages or all activity on Telegram. Repeated history reads can record the same message again."
TIME_NOTE = "Times use the collector's observation clock in UTC, not message sending times. An empty interval means no observations were counted; consult coverage for interruptions."
PEOPLE_NOTE = "Participants are ranked by new, historical and recovered message observations. Edits and deletions are not attributed to a person."
PRIVACY_NOTE = "Aliases apply to charts only. Source records remain unchanged."
REVIEW_TITLE = "Examination notes"
REVIEW_NOTE = "Written by the report's author. These statements are sealed with the report; they are separate from the software's checks."
REVIEW_FIELDS = {"question": "Question examined", "method": "Method used", "findings": "Findings", "conclusion": "Conclusion"}
KINDS = {"new": "New-message observations", "snapshot": "History observations", "recovered": "Recovered-message observations",
         "edited": "Edit observations", "deleted": "Deletion observations", "missing": "Missing on recheck"}
COLORS = {"new": "#247e8c", "snapshot": "#5776b3", "recovered": "#8c70aa", "edited": "#b28226",
          "deleted": "#b65264", "missing": "#7e8794"}
DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")

CSS = """
.metric-chart{width:100%;height:72px;display:block;margin:8px 0}.metric-bar{fill:#5776b3}
.report-analytics{--chart-ink:var(--chart-accent)}.analytics-meta{font:11px/1.8 ui-monospace,monospace;overflow-wrap:anywhere;color:var(--muted)}
.analytics-totals{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin:24px 0}
.analytics-totals div{padding:18px;background:var(--card,var(--paper));min-width:0}.analytics-totals b{font:30px/1.3 Georgia,serif;display:block}
.analytics-totals span{font-size:11px;overflow-wrap:anywhere}.analytics-figure{margin:28px 0;padding:22px;border:1px solid var(--line);break-inside:avoid;min-width:0}
.analytics-figure figcaption{font-weight:650;font-size:16px;margin-bottom:12px}.analytics-figure p{font-size:12px;line-height:1.7;color:var(--muted)}
.analytics-figure svg{width:100%;height:auto;display:block;direction:ltr}.analytics-svg-label{fill:var(--ink);font:12px system-ui,sans-serif}
.analytics-axis{fill:var(--muted);font:10px ui-monospace,monospace}.analytics-gridline{stroke:var(--line);stroke-width:1}
.analytics-legend{list-style:none;display:flex;flex-wrap:wrap;gap:8px 18px;padding:0;font-size:11px}.analytics-legend li{display:flex;gap:6px;align-items:center}
.analytics-legend svg{width:9px;height:9px;display:inline-block}.analytics-table{margin-top:18px}.analytics-table summary{cursor:pointer;font-size:12px;color:var(--accent);padding:8px 0}
.analytics-data{width:100%;border-collapse:collapse;font-size:11px;table-layout:fixed}.analytics-data th,.analytics-data td{border-bottom:1px solid var(--line);padding:8px 5px;overflow-wrap:anywhere;text-align:start}
.analytics-print-data{display:none}
.analytics-bar{display:grid;grid-template-columns:minmax(110px,1fr) minmax(50px,2fr) 64px;gap:14px;align-items:center;margin:16px 0;font-size:12px}
.analytics-bar-label{overflow-wrap:anywhere}.analytics-bar-value{text-align:end;font-variant-numeric:tabular-nums}.analytics-bar-track{background:var(--line);height:12px}
.analytics-bar-fill{background:var(--chart-ink);height:100%;min-width:1px}.analytics-pair{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}.analytics-pair>.analytics-figure{margin-top:0}
.examination-text{white-space:pre-wrap;overflow-wrap:anywhere;font-size:14px;line-height:1.85;max-width:80ch}.examination-part{border-top:1px solid var(--line);padding-top:18px;margin-top:24px;break-inside:avoid}
[data-report-design=classic] .examination-part{display:grid;grid-template-columns:minmax(130px,1fr) minmax(0,3fr);gap:24px}
[data-report-design=classic] .examination-part h3{font:11px/1.8 system-ui,sans-serif;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
[data-report-design=classic] .examination-text{font-family:Georgia,'Times New Roman',serif;font-size:16px}
@media(max-width:800px){.analytics-pair{grid-template-columns:1fr}.analytics-totals{grid-template-columns:repeat(2,minmax(0,1fr))}.analytics-figure{padding:14px}.analytics-bar{grid-template-columns:minmax(70px,1fr) minmax(30px,1fr) 52px;gap:8px}}
@media(max-width:600px){[data-report-design=classic] .examination-part{display:block}}
@media print{.analytics-pair{display:block}.analytics-table{display:none}.analytics-print-data{display:block}.analytics-figure{break-inside:auto;padding:12px}.analytics-totals div{padding:10px}}
"""


def text_keys():
    return [TITLE, INTRO, TIME_NOTE, PEOPLE_NOTE, PRIVACY_NOTE, REVIEW_TITLE, REVIEW_NOTE, *REVIEW_FIELDS.values(),
            *KINDS.values(), *DAYS, "Recorded activity over time", "Observation times by weekday and hour", "Most observed participants",
            "Activity by chat", "Exact figures", "Period (UTC)", "Observations", "First record", "Last record", "Source file",
            "No observations in this selection.", "This chart exceeds the grouping limit. Exact overall counts remain available.",
            "Observations with an unusable time: {n}", "Participant {n}", "Sender {id}", "Chat {id}", "Unknown", "Other",
            "All bars start at zero. Values are counts, not percentages.", "Hour (UTC)", "Counts by category", "Report sections", "Record composition", "THE RECORD IN NUMBERS", *metric_texts()]


def _e(value):
    return escape(str(value), quote=True)


def label(row, say):
    return say(row["label"], **row.get("label_values", {}))


def activity_bins(rows, maximum=36):
    if not rows:
        return []
    monthly = len(rows[0]["period"]) == 7
    def number(period):
        return int(period[:4])*12 + int(period[5:7])-1 if monthly else date.fromisoformat(period).toordinal()
    def period(value):
        return f"{value//12:04d}-{value%12+1:02d}" if monthly else date.fromordinal(value).isoformat()
    first, last = min(number(r["period"]) for r in rows), max(number(r["period"]) for r in rows)
    width = max(1, math.ceil((last-first+1)/maximum))
    result = []
    for start in range(first, last+1, width):
        end = min(start+width-1, last)
        result.append({"period": period(start) if start == end else period(start)+" – "+period(end),
                       "counts": dict.fromkeys(KINDS, 0), "total": 0})
    for row in rows:
        target = result[(number(row["period"])-first)//width]
        target["total"] += row["total"]
        for kind in KINDS:
            target["counts"][kind] += row["counts"].get(kind, 0)
    return result


def _table(headers, rows, say):
    table = ('<table class="analytics-data"><thead><tr>'
            + ''.join('<th scope="col">'+_e(h)+'</th>' for h in headers)+'</tr></thead><tbody>'
            + ''.join('<tr>'+''.join('<td>'+_e(v)+'</td>' for v in row)+'</tr>' for row in rows)+'</tbody></table>')
    return ('<details class="analytics-table"><summary>'+_e(say("Exact figures"))+'</summary>'+table+'</details>'
            + '<div class="analytics-print-data">'+table+'</div>')


def _unavailable(chart, say):
    if chart.get("status", "available") != "available":
        return '<p>'+_e(say("This chart exceeds the grouping limit. Exact overall counts remain available."))+'</p>'
    return ''


def axis_top(rows):
    maximum = max(r["total"] for r in rows) or 1
    return maximum + maximum % 2


def activity_svg(rows, say):
    if not rows:
        return '<p>'+_e(say("No observations in this selection."))+'</p>'
    maximum = axis_top(rows)
    parts = ['<svg viewBox="0 0 720 245" role="img" aria-label="'+_e(say("Recorded activity over time"))+'">']
    for value in (0, maximum/2, maximum):
        y = 200-170*value/maximum
        parts.append(f'<line class="analytics-gridline" x1="50" y1="{y:.2f}" x2="705" y2="{y:.2f}"/><text class="analytics-axis" x="43" y="{y+4:.2f}" text-anchor="end">{value:g}</text>')
    step = 650/len(rows)
    for index, row in enumerate(rows):
        y = 200
        parts.append('<g><title>'+_e(row["period"]+' · '+str(row["total"]))+'</title>')
        for kind, color in COLORS.items():
            height = 170*row["counts"].get(kind, 0)/maximum
            y -= height
            if height:
                parts.append(f'<rect x="{52+index*step:.2f}" y="{y:.2f}" width="{max(1,step-3):.2f}" height="{height:.2f}" fill="{color}"/>')
        parts.append('</g>')
    parts.append('<text class="analytics-axis" x="50" y="223">'+_e(rows[0]["period"].split(' – ')[0])+'</text>')
    parts.append('<text class="analytics-axis" x="705" y="223" text-anchor="end">'+_e(rows[-1]["period"].split(' – ')[-1])+'</text></svg>')
    return ''.join(parts)


def heat_svg(chart, say):
    rows = chart["rows"]
    maximum = max((value for row in rows for value in row), default=0) or 1
    parts = ['<svg viewBox="0 0 760 226" role="img" aria-label="'+_e(say("Observation times by weekday and hour"))+'">']
    for hour in range(0, 24, 3):
        parts.append(f'<text class="analytics-axis" x="{144+hour*25}" y="16" text-anchor="middle">{hour:02d}</text>')
    for day, row in enumerate(rows):
        parts.append(f'<text class="analytics-svg-label" x="125" y="{43+day*25}" text-anchor="end">'+_e(say(DAYS[day]))+'</text>')
        for hour, value in enumerate(row):
            parts.append(f'<rect x="{133+hour*25}" y="{27+day*25}" width="22" height="22" rx="2" fill="#247e8c" fill-opacity="{.08+.92*value/maximum:.3f}"><title>'
                         +_e(say(DAYS[day])+f' {hour:02d}:00 UTC · {value}')+'</title></rect>')
    parts.append('<text class="analytics-axis" x="735" y="220" text-anchor="end">'+_e(say("Hour (UTC)"))+'</text></svg>')
    return ''.join(parts)


def bars_html(chart, say):
    if error := _unavailable(chart, say):
        return error
    rows = chart["rows"]
    maximum = max((r["total"] for r in rows), default=0) or 1
    parts = ['<div class="rank-chart">']
    for row in rows:
        parts.append('<div class="rank-row"><span class="rank-label">'+_e(label(row, say))+'</span><strong>'+str(row["total"])
                     +'</strong><svg aria-hidden="true" viewBox="0 0 800 10" preserveAspectRatio="none">'
                     +'<rect class="chart-track" width="800" height="10" rx="3"/><rect class="chart-bar" width="'
                     +str(800*row["total"]/maximum)+'" height="10" rx="3"/></svg></div>')
    if not rows:
        return '<p>'+_e(say("No observations in this selection."))+'</p>'
    parts.append('</div>')
    parts.append(_table([say("Observations"), say("First record"), say("Last record")],
                        [(label(r, say)+' · '+str(r["total"]), '#'+str(r["first_seq"]) if r.get("first_seq") else '—',
                          '#'+str(r["last_seq"]) if r.get("last_seq") else '—') for r in rows], say))
    return ''.join(parts)


def html(data, say):
    if not data:
        return ''
    parts = ['<section class="card report-analytics" id="report-analytics"><div class="analytics-heading"><div><p class="eyebrow">'+_e(say("THE RECORD IN NUMBERS"))+'</p><h2>'+_e(say(TITLE))+'</h2></div><span class="analytics-basis">UTC</span></div><p>'+_e(say(INTRO))+'</p>']
    source = data.get("source") or {}
    parts.append('<p class="analytics-meta">'+_e(say("Source file"))+': '+_e(source.get("file", "events.jsonl"))+'<br>SHA-256 · '+_e(source.get("sha256") or '—')+'</p>')
    parts.append('<p class="analytics-meta">'+_e(str(data.get("first_observed_at") or '—')+' → '+str(data.get("last_observed_at") or '—'))
                 +' · UTC<br>'+_e(say("Observations"))+': '+str(data["activity_events"])+'</p>')
    parts.append('<div class="analytics-totals">'+''.join('<div><b>'+str(data["totals"].get(kind, 0))+'</b><span>'+_e(say(title))+'</span></div>' for kind, title in KINDS.items())+'</div>')
    if chart := data.get("activity"):
        parts.append('<figure class="analytics-figure chart-card chart-activity"><figcaption>'+_e(say("Recorded activity over time"))+'</figcaption><p>'+_e(say(TIME_NOTE))+'</p>')
        if error := _unavailable(chart, say):
            parts.append(error)
        else:
            rows = activity_bins(chart["rows"])
            parts.append(activity_svg(rows, say))
            parts.append('<ul class="analytics-legend">'+''.join('<li><svg width="9" height="9" aria-hidden="true"><rect width="9" height="9" fill="'+COLORS[k]+'"/></svg>'+_e(say(v))+'</li>' for k, v in KINDS.items())+'</ul>')
            parts.append(_table([say("Period (UTC)"), say("Observations"), say("Counts by category")],
                               [(r["period"], r["total"], '; '.join(say(KINDS[k])+': '+str(v) for k, v in r["counts"].items() if v)) for r in rows], say))
        parts.append('</figure>')
    if chart := data.get("hourly"):
        parts.append('<figure class="analytics-figure chart-card chart-heatmap"><figcaption>'+_e(say("Observation times by weekday and hour"))+'</figcaption>'+heat_svg(chart, say))
        parts.append(_table([say("Period (UTC)"), say("Observations")],
                           [(say(DAYS[d])+f' {hour:02d}:00', value) for d, row in enumerate(chart["rows"]) for hour, value in enumerate(row)], say))
        parts.append('</figure>')
    parts.append('<div class="analytics-pair">')
    for key, title in (("participants", "Most observed participants"), ("chats", "Activity by chat")):
        if chart := data.get(key):
            parts.append('<figure class="analytics-figure chart-card chart-'+key+'"><figcaption>'+_e(say(title))+'</figcaption>')
            if key == 'participants':
                parts.append('<p>'+_e(say(PEOPLE_NOTE))+'</p>')
                if data.get("participant_labels") != "ids":
                    parts.append('<p>'+_e(say(PRIVACY_NOTE))+'</p>')
            parts.append('<p>'+_e(say("Observations"))+': '+str(chart["total"])+'</p>'+bars_html(chart, say)+'</figure>')
    parts.append('</div>')
    if composition := data.get("composition"):
        rows = [{"label": KINDS[k], "total": value} for k, value in composition.items()]
        parts.append('<figure class="analytics-figure chart-card chart-composition"><figcaption>'+_e(say("Record composition"))+'</figcaption>'
                     +bars_html({"rows": rows}, say)+'</figure>')
    parts.append('<p>'+_e(say("All bars start at zero. Values are counts, not percentages."))+'</p>')
    if data.get("invalid_time_events"):
        parts.append('<p>'+_e(say("Observations with an unusable time: {n}", n=data["invalid_time_events"]))+'</p>')
    return ''.join(parts)+'</section>'


def examination_html(data, say):
    if not data:
        return ''
    parts = ['<section class="card" id="examination"><h2>'+_e(say(REVIEW_TITLE))+'</h2><p>'+_e(say(REVIEW_NOTE))+'</p>']
    for key, title in REVIEW_FIELDS.items():
        if value := data.get(key):
            parts.append('<div class="examination-part"><h3>'+_e(say(title))+'</h3><p class="examination-text" dir="auto">'+_e(value)+'</p></div>')
    return ''.join(parts)+'</section>'


def _rgb(value):
    return tuple(int(value[i:i+2], 16) for i in (1, 3, 5))


def pdf(lay, data):
    if not data:
        return
    say, pdf = lay.say, lay.pdf
    if not getattr(lay, "composition_chapter", False):
        pdf.add_page()
    lay.section(say(TITLE), say(INTRO))
    lay.kv([(say("Source file"), data.get("source", {}).get("file", "events.jsonl")),
            ("SHA-256", data.get("source", {}).get("sha256"))])
    lay.grid([say("Counts by category"), say("Observations")], [(say(title), data["totals"].get(kind, 0)) for kind, title in KINDS.items()], (75,25))
    if chart := data.get("activity"):
        lay.heading(say("Recorded activity over time"))
        lay.text(say(TIME_NOTE), size=8)
        if chart.get("status") != "available":
            lay.text(say("This chart exceeds the grouping limit. Exact overall counts remain available."), size=9)
        elif rows := activity_bins(chart["rows"]):
            if pdf.get_y()+85 > pdf.page_break_trigger:
                pdf.add_page()
            left, top, width, height = pdf.l_margin+10, pdf.get_y()+5, pdf.epw-12, 43
            maximum = axis_top(rows)
            with pdf.local_context(draw_color=(190,197,200)):
                for frac in (0,.5,1):
                    pdf.line(left, top+height*frac, left+width, top+height*frac)
            for fraction in (0,.5,1):
                pdf.set_xy(pdf.l_margin,top+height*(1-fraction)-1.5)
                pdf.set_font("Sans",size=6)
                pdf.cell(8,3,f'{maximum*fraction:g}',align="R")
            step = width/len(rows)
            for index, row in enumerate(rows):
                y = top+height
                for kind, color in COLORS.items():
                    bar = height*row["counts"].get(kind,0)/maximum
                    y -= bar
                    if bar:
                        with pdf.local_context(fill_color=_rgb(color)):
                            pdf.rect(left+index*step, y, max(.2,step-.8), bar, style="F")
            pdf.set_y(top+height+3)
            lay.text(rows[0]["period"]+'  →  '+rows[-1]["period"]+' · UTC', size=8)
            kinds=list(KINDS)
            for start in (0,3):
                y=pdf.get_y()+1
                ends=[]
                for column, kind in enumerate(kinds[start:start+3]):
                    x=pdf.l_margin+column*pdf.epw/3
                    with pdf.local_context(fill_color=_rgb(COLORS[kind])):
                        pdf.rect(x,y+1,2.5,2.5,style="F")
                    pdf.set_xy(x+4,y)
                    pdf.set_font("Sans",size=7)
                    pdf.multi_cell(pdf.epw/3-6,3.5,say(KINDS[kind]),align=lay.align[0])
                    ends.append(pdf.get_y())
                pdf.set_y(max(ends)+1)
            lay.gap(3)
            lay.heading(say("Exact figures"))
            lay.grid([say("Period (UTC)"), say("New message"), say("History snapshot"), say("Recovered message"),
                      say("Edits"), say("Deletions"), say("Missing on recheck")],
                     [(r["period"], *[r["counts"].get(kind, 0) for kind in KINDS]) for r in rows],
                     (28,12,12,12,12,12,12))
        else:
            lay.text(say("No observations in this selection."),size=9)
    if chart := data.get("hourly"):
        lay.heading(say("Observation times by weekday and hour"))
        if pdf.get_y()+65 > pdf.page_break_trigger:
            pdf.add_page()
        rows = chart["rows"]
        maximum = max((v for row in rows for v in row), default=0) or 1
        left, top, step = pdf.l_margin+32, pdf.get_y()+3, (pdf.epw-32)/24
        for day, row in enumerate(rows):
            pdf.set_xy(pdf.l_margin, top+day*6)
            pdf.set_font("Sans",size=7)
            pdf.multi_cell(30,3,say(DAYS[day]),align=lay.align[0])
            for hour, value in enumerate(row):
                fraction = value/maximum
                color = tuple(round(a+(b-a)*fraction) for a,b in zip((231,240,241),(36,126,140)))
                with pdf.local_context(fill_color=color):
                    pdf.rect(left+hour*step,top+day*6,step-.5,5.4,style="F")
        for hour in range(0,24,3):
            pdf.set_xy(left+hour*step,top+44)
            pdf.set_font("Sans",size=6)
            pdf.cell(step,3,f'{hour:02d}')
        pdf.set_y(top+50)
        lay.text(say(TIME_NOTE),size=8)
        lay.heading(say("Exact figures"))
        for start in (0,12):
            lay.grid([say("Hour (UTC)"), *[f'{hour:02d}' for hour in range(start,start+12)]],
                     [(say(DAYS[day]), *row[start:start+12]) for day,row in enumerate(rows)],
                     [24]+[76/12]*12)
    for key, title in (("participants","Most observed participants"),("chats","Activity by chat")):
        if not (chart := data.get(key)):
            continue
        lay.heading(say(title))
        if key == 'participants':
            lay.text(say(PEOPLE_NOTE),size=8)
            if data.get("participant_labels") != 'ids':
                lay.text(say(PRIVACY_NOTE),size=8)
        if chart.get("status") != 'available':
            lay.text(say("This chart exceeds the grouping limit. Exact overall counts remain available."),size=9)
            continue
        rows = chart["rows"]
        maximum = max((r["total"] for r in rows),default=0) or 1
        for row in rows:
            if pdf.get_y()+15 > pdf.page_break_trigger:
                pdf.add_page()
            lay.text(label(row,say)+'  ·  '+str(row["total"]),size=8)
            y = pdf.get_y()
            with pdf.local_context(fill_color=(36,126,140)):
                pdf.rect(pdf.l_margin,y,max(.1,pdf.epw*row["total"]/maximum),2.3,style="F")
            pdf.set_y(y+5)
        if not rows:
            lay.text(say("No observations in this selection."),size=9)
    if composition := data.get("composition"):
        lay.need(90)
        lay.heading(say("Record composition"))
        maximum = max(composition.values(), default=0) or 1
        for kind, count in composition.items():
            lay.need(15)
            lay.text(say(KINDS[kind])+" · "+str(count), size=8)
            with pdf.local_context(fill_color=_rgb(COLORS[kind])):
                pdf.rect(pdf.l_margin, pdf.get_y(), pdf.epw*count/maximum, 2, style="F")
            lay.gap(5)
    lay.text(say("All bars start at zero. Values are counts, not percentages."),size=8)
    if data.get("invalid_time_events"):
        lay.text(say("Observations with an unusable time: {n}",n=data["invalid_time_events"]),size=8)


def examination_pdf(lay, data):
    if not data:
        return
    lay.section(lay.say(REVIEW_TITLE),lay.say(REVIEW_NOTE))
    for key, title in REVIEW_FIELDS.items():
        if value := data.get(key):
            lay.heading(lay.say(title))
            lay.text(value,size=9)


METRICS_TITLE = "Anomaly indicators"
METRICS_INTRO = "Computed from events.jsonl by the listed processors. They point at what to check, not at what happened."


def metric_texts():
    from . import metrics
    found = [METRICS_TITLE, METRICS_INTRO, "Processors that ran: {list}", "Method", "Flagged for review: {n}",
             "Showing the latest {shown} of {total} rows.", "Chat {id}, {day}: {found} first-time posters (median {base}), "
             "{messages} messages (median {base_messages})"]
    for cls in metrics.load().values():
        found += [cls.title, cls.methodology, *cls.columns]
    return found


def _metric_bars(rows, column):
    values = [row[column] if isinstance(row[column], (int, float)) else 0 for row in rows]
    top = max(values, default=0) or 1
    width = max(len(values), 1)
    bars = "".join('<rect x="%.3f" y="%.3f" width="%.3f" height="%.3f" class="metric-bar"/>'
                   % (index * 1000 / width + 1, 100 - value * 96 / top, max(1000 / width - 2, 1), value * 96 / top)
                   for index, value in enumerate(values))
    return ('<svg class="metric-chart" viewBox="0 0 1000 100" preserveAspectRatio="none" role="img" aria-hidden="true">'
            + bars + '</svg>')


def metrics_html(data, say):
    if not data or not data.get("processors"):
        return ''
    ran = ', '.join(p["name"] + ' v' + str(p["version"]) for p in data["processors"])
    parts = ['<section class="card report-analytics" id="report-metrics"><h2>' + _e(say(METRICS_TITLE)) + '</h2><p>'
             + _e(say(METRICS_INTRO)) + '</p><p class="analytics-meta">' + _e(say("Processors that ran: {list}", list=ran))
             + '</p>']
    for item in data["processors"]:
        columns, rows = [say(c) for c in item["columns"]], item.get("rows") or []
        parts.append('<figure class="analytics-figure chart-card metric-figure"><figcaption>' + _e(say(item["title"]))
                     + ' <span class="analytics-basis">' + _e(item["name"]) + ' v' + _e(item["version"]) + '</span></figcaption>')
        if rows and len(rows[0]) > 1 and isinstance(rows[0][1], (int, float)):
            parts.append(_metric_bars(rows, 1))
        if not rows:
            parts.append('<p>' + _e(say("No observations in this selection.")) + '</p>')
        else:
            if item.get("rows_total", len(rows)) > len(rows):
                parts.append('<p>' + _e(say("Showing the latest {shown} of {total} rows.", shown=len(rows),
                                             total=item["rows_total"])) + '</p>')
            parts.append(_table(columns, rows, say))
        if item.get("flags_total"):
            parts.append('<p><b>' + _e(say("Flagged for review: {n}", n=item["flags_total"])) + '</b></p><ul>' + ''.join(
                '<li>' + _e(say("Chat {id}, {day}: {found} first-time posters (median {base}), {messages} messages "
                                "(median {base_messages})", id=f["chat_id"], day=f["day"], found=f["first_time_posters"],
                                base=f["baseline"], messages=f["messages"], base_messages=f["baseline_messages"]))
                + '</li>' for f in item.get("flags") or []) + '</ul>')
        parts.append('<p class="analytics-meta">' + _e(say("Method")) + ': ' + _e(say(item["methodology"])) + '</p></figure>')
    return ''.join(parts) + '</section>'


def metrics_pdf(lay, data):
    if not data or not data.get("processors"):
        return
    say = lay.say
    lay.section(say(METRICS_TITLE), say(METRICS_INTRO))
    lay.text(say("Processors that ran: {list}", list=', '.join(p["name"] + ' v' + str(p["version"])
                                                               for p in data["processors"])), size=8)
    for item in data["processors"]:
        lay.heading(say(item["title"]) + ' · ' + item["name"] + ' v' + str(item["version"]))
        rows = item.get("rows") or []
        if rows:
            widths = tuple(round(100 / len(item["columns"]), 2) for _ in item["columns"])
            lay.grid([say(c) for c in item["columns"]], [[str(value) for value in row] for row in rows[-40:]], widths)
        else:
            lay.text(say("No observations in this selection."), size=8)
        for flag in (item.get("flags") or [])[:20]:
            lay.text(say("Chat {id}, {day}: {found} first-time posters (median {base}), {messages} messages (median "
                         "{base_messages})", id=flag["chat_id"], day=flag["day"], found=flag["first_time_posters"],
                         base=flag["baseline"], messages=flag["messages"], base_messages=flag["baseline_messages"]), size=8)
        lay.text(say("Method") + ': ' + say(item["methodology"]), size=7.5)
