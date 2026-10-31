"""Render README cards and buttons in TgWitness's casework palette.

Navy surfaces, ice-blue signals and warm accents match the repository covers.
Outlined Manrope captions need no installed or remotely loaded fonts.
"""
import argparse
from html import escape
from pathlib import Path
import xml.etree.ElementTree as ET

OUT = Path(__file__).resolve().parents[1] / "docs/assets/presentation"
FONT = "Segoe UI, Arial, sans-serif"
BLUE, GOLD, STEEL = "#8ccfff", "#dfbd86", "#a0b6cb"
INK, MUTED = "#edf5fc", "#a0b6cb"
BUTTON_BLUE, BUTTON_GOLD, BUTTON_STEEL = "#245170", "#685238", "#354c63"


def svg(width, height, title, body):
    title = escape(title, quote=True)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-label="{title}">'
            f'<title>{title}</title><g font-family="{FONT}">{body}</g></svg>\n')


def label(text, x, y, size, color=MUTED, weight=400, spacing=0):
    return (f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" '
            f'font-weight="{weight}" letter-spacing="{spacing}">{escape(text)}</text>')


def card(width, height, kicker, title, lines, color, *, large=False, still=False, delay=0):
    surface_id = "surface-" + kicker[:2]
    result = (f'<defs><linearGradient id="{surface_id}" x1="0" y1="0" x2="1" y2="1">'
              '<stop stop-color="#0c1c2e"/><stop offset="1" stop-color="#070f1b"/></linearGradient></defs>'
              f'<rect x="1" y="1" width="{width-2}" height="{height-2}" rx="14" fill="url(#{surface_id})" stroke="#2d4359"/>'
              f'<path d="M27 1H{width-27}" stroke="{color}" stroke-opacity=".7" stroke-width="2"/>')
    result += label(kicker, 26, 42, 18 if large else 13, color, 600, 1.6)
    result += f'<circle cx="{width-30}" cy="37" r="4" fill="{color}">'
    if not still:
        result += f'<animate attributeName="opacity" values=".3;1;.3" dur="4s" begin="{delay}s" repeatCount="indefinite"/>'
    result += '</circle>'
    result += label(title, 26, 105 if large else 97, 40 if large else 27, INK, 650, -.6)
    for index, line in enumerate(lines):
        result += label(line, 26, (160 + index*39) if large else (145 + index*27), 27 if large else 17)
    return result


def panel(height, kicker, title, subtitle, color):
    return ('<defs><linearGradient id="paper" x1="0" y1="0" x2="1" y2="1">'
            '<stop stop-color="#10263c"/><stop offset="1" stop-color="#070f1b"/></linearGradient>'
            '<pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">'
            '<circle cx="1" cy="1" r=".7" fill="#8ccfff" opacity=".12"/></pattern></defs>'
            f'<rect x="1" y="1" width="598" height="{height-2}" rx="20" fill="url(#paper)" stroke="#36516b"/>'
            f'<rect x="2" y="2" width="596" height="{height-4}" rx="20" fill="url(#grid)"/>'
            f'<path d="M32 1H568" stroke="{color}" stroke-width="2"/>'
            + label(kicker, 32, 44, 19, color, 600, 1.5)
            + label(title, 32, 99, 38, INK, 650, -.8)
            + label(subtitle, 32, 139, 25))


def box(x, y, width, height, *, color="#36516b", fill="#102238", radius=12):
    return (f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
            f'rx="{radius}" fill="{fill}" stroke="{color}" stroke-width="1.5"/>')


def centered(text, x, y, size, color=MUTED, weight=400):
    return label(text, x, y, size, color, weight).replace('<text ', '<text text-anchor="middle" ', 1)


def reveal(body, still, start=.25):
    if still:
        return '<g>' + body + '</g>'
    # The final state holds long enough to read before the illustrated flow repeats.
    return ('<g>'
            f'<animate attributeName="opacity" values="0;0;1;1;0" keyTimes="0;{start};{start+.08};.91;1" dur="8s" repeatCount="indefinite"/>'
            f'<animateTransform attributeName="transform" type="translate" values="0 12;0 12;0 0;0 0;0 12" keyTimes="0;{start};{start+.08};.91;1" dur="8s" repeatCount="indefinite"/>'
            + body + '</g>')


def trace(path, color, still, start=0, end=1):
    body = f'<path d="{path}" fill="none" stroke="#36516b" stroke-width="2"/>'
    if still:
        return body + f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2" opacity=".7"/>'
    points, times = ["0"], ["0"]
    if start:
        points.append("0")
        times.append(str(start))
    points.append("1")
    times.append(str(end))
    if end < 1:
        points.append("1")
        times.append("1")
    body += (f'<circle r="6" fill="{color}"><animateMotion path="{path}" '
             f'keyPoints="{";".join(points)}" keyTimes="{";".join(times)}" calcMode="linear" dur="8s" repeatCount="indefinite"/>'
             '<animate attributeName="opacity" values=".4;1;.4" dur="2s" repeatCount="indefinite"/></circle>')
    return body


def feature_footer(body, first):
    body += '<path d="M32 480H568" stroke="#30495f"/>'
    body += label(first, 32, 516, 25, INK)
    return body


def export_feature(still):
    body = panel(540, "01 / CHAT EXPORT", "Export a chat.", "Choose a chat. Save its history.", BLUE)
    body += box(24, 168, 552, 294, fill="#091726")
    body += box(45, 197, 212, 209)
    body += label("CHAT HISTORY", 62, 228, 18, BLUE, 600, .6)
    for i, width in enumerate([157, 124, 149]):
        yy = 247 + 44*i
        bubble = box(62, yy, width, 30, fill="#1b354d", color="#2e526e", radius=7)
        bubble += f'<path d="M74 {yy+15}h{width-25}" stroke="#8baac3" stroke-width="3" stroke-linecap="round"/>'
        body += reveal(bubble, still, .03+i*.05)
    body += trace("M258 298H335", BLUE, still, .12, .4)
    body += '<path d="m323 290 10 8-10 8" fill="none" stroke="#8ccfff" stroke-width="2"/>'
    docs = box(346, 211, 207, 184, color=BLUE)
    docs += '<path d="M346 253H553" stroke="#36516b"/>'
    docs += label("EXPORT", 365, 239, 20, BLUE, 600, 1)
    docs += label("chat.html", 365, 290, 26, INK, 600)
    docs += label("chat.json", 365, 335, 26, INK, 600)
    docs += label("Read · inspect", 365, 370, 20)
    body += reveal(docs, still, .32)
    ready = box(348, 412, 202, 32, color="#4c7c70", fill="#15312d", radius=7)
    ready += centered("SIGNED ZIP", 449, 435, 19, "#98d8c0", 600)
    body += reveal(ready, still, .58)
    return feature_footer(body, "Read the history offline.")


def investigate_feature(still):
    body = panel(540, "02 / INVESTIGATION", "Follow the leads.", "Search across recorded chats.", GOLD)
    body += box(24, 168, 552, 294, fill="#091726")
    body += box(48, 188, 504, 48, color="#6e624c")
    body += '<circle cx="72" cy="210" r="9" fill="none" stroke="#dfbd86" stroke-width="2"/><path d="m79 217 7 7" stroke="#dfbd86" stroke-width="2"/>'
    body += label("pay.example.invalid", 103, 220, 24, INK)
    body += trace("M300 237V253H157V269", GOLD, still, .05, .25)
    body += trace("M300 237V253H443V269", GOLD, still, .1, .37)
    for i, x in enumerate([48, 334]):
        result = box(x, 270, 218, 78, color="#6e624c")
        result += label("CHAT " + ("A" if i == 0 else "B"), x+17, 297, 18, GOLD, 600, 1)
        result += label("Link mentioned", x+17, 329, 23, INK)
        body += reveal(result, still, .17+i*.15)
    body += trace("M157 349V369H300V388", GOLD, still, .45, .68)
    body += trace("M443 349V369H300V388", GOLD, still, .5, .73)
    result = box(155, 390, 290, 51, color="#6e624c")
    result += centered("Open source records", 300, 423, 23, INK, 600)
    body += reveal(result, still, .64)
    return feature_footer(body, "Every lead has a source.")


def history_feature(still):
    body = panel(540, "03 / SAVED VERSIONS", "Keep the changes.", "Capture edits and deletion notices.", BLUE)
    body += box(24, 168, 552, 294, fill="#091726")
    body += trace("M69 213V411", BLUE, still, .05, .7)
    rows = [(195, "Meet at 16:00", "CAPTURED", BLUE, .02),
            (282, "Meet at 17:30", "SAVED EDIT", GOLD, .3),
            (369, "Deletion observed", "RECORD RETAINED", "#98d8c0", .6)]
    for i, (y, title, caption, color, start) in enumerate(rows):
        row = box(91, y, 460, 71, color=color)
        row += f'<circle cx="69" cy="{y+35}" r="8" fill="{color}"/>'
        row += label(title, 110, y+29, 26, INK, 600)
        row += label(caption, 110, y+57, 18, color, 600, .6)
        body += row if i == 0 else reveal(row, still, start)
    return feature_footer(body, "Observed versions stay saved.")


def features(still):
    entries = [("export", export_feature, "Export visible chat history to a signed HTML and JSON bundle."),
               ("investigate", investigate_feature, "Illustrated investigation: search recorded chats for a shared link, then open the source records. This is a workflow diagram, not an automatic graph interface."),
               ("history", history_feature, "A captured message, its observed edit and a deletion notice remain separate journal records.")]
    for name, draw, description in entries:
        path = OUT / ("readme-feature-" + name + ("-static" if still else "") + ".svg")
        path.write_text(svg(600, 540, description, draw(still)), encoding="utf-8")


def card_layouts(names, source_prefix, output_prefix, card_height, title):
    """One responsive image keeps each desktop row intact at browser zoom levels."""
    ns = "http://www.w3.org/2000/svg"
    for mobile in (False, True):
        for still in (False, True):
            width, height = ((600, len(names)*(card_height+16)-16) if mobile
                             else (len(names)*616-16, card_height))
            root = ET.Element("{" + ns + "}svg", {"width": str(width), "height": str(height), "viewBox": f"0 0 {width} {height}", "role": "img", "aria-label": title})
            ET.SubElement(root, "{" + ns + "}title").text = title
            for i, name in enumerate(names):
                card = ET.parse(OUT / (source_prefix + name + ("-static" if still else "") + ".svg")).getroot()
                # Nested SVGs share the document's ID namespace.
                identifiers = {node.attrib["id"]: name + "-" + node.attrib["id"] for node in card.iter() if "id" in node.attrib}
                for node in card.iter():
                    for key, value in list(node.attrib.items()):
                        if key == "id":
                            node.set(key, identifiers[value])
                        elif value.startswith("#") and value[1:] in identifiers:
                            node.set(key, "#" + identifiers[value[1:]])
                        elif "url(#" in value:
                            for old, new in identifiers.items():
                                value = value.replace("url(#" + old + ")", "url(#" + new + ")")
                            node.set(key, value)
                card.set("x", "0" if mobile else str(i*616))
                card.set("y", str(i*(card_height+16)) if mobile else "0")
                root.append(card)
            name = output_prefix + ("-mobile" if mobile else "") + ("-static" if still else "") + ".svg"
            (OUT / name).write_text(ET.tostring(root, encoding="unicode"), encoding="utf-8")


def feature_layouts():
    card_layouts(("export", "investigate", "history"), "readme-feature-", "readme-features", 540,
                 "Export a chat. Follow the leads. Keep the changes. Illustrated TgWitness workflows.")


def service_layouts():
    card_layouts(("apprise", "s3"), "readme-card-", "readme-services", 420,
                 "Keep the investigation running: Apprise notifications and encrypted S3 off-site copies.")


def services(still):
    body = panel(420, "APPRISE", "Notifications", "Changes, issues and daily summaries.", BLUE)
    body += box(28, 213, 157, 101)
    body += centered("EVENT", 106, 246, 18, BLUE, 600)
    body += centered("Chat changed", 106, 283, 21, INK)
    body += trace("M186 263H268", BLUE, still, .04, .28)
    body += '<circle cx="300" cy="263" r="32" fill="#17334c" stroke="#8ccfff" stroke-width="2"/>'
    body += '<path d="M287 271h26l-4-8v-8a9 9 0 0 0-18 0v8Zm9 7h8" fill="none" stroke="#edf5fc" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>'
    body += centered("APPRISE", 300, 321, 18, BLUE, 600)
    for i, (y, destination) in enumerate([(180, "Messenger"), (240, "Email"), (300, "Webhook")]):
        body += trace(f"M333 263H370V{y+24}H404", BLUE, still, .3+i*.08, .6+i*.08)
        endpoint = box(406, y, 167, 48)
        endpoint += centered(destination, 489, y+31, 21, INK, 600)
        body += reveal(endpoint, still, .48+i*.08)
    body += label("Send to your configured destinations.", 32, 391, 23)
    (OUT / ("readme-card-apprise" + ("-static" if still else "") + ".svg")).write_text(svg(600, 420, "Apprise routes events to configured notification destinations.", body), encoding="utf-8")

    body = panel(420, "S3 STORAGE", "Off-site copy", "Encrypt here. Store elsewhere.", GOLD)
    for i, x in enumerate([43, 52, 61]):
        body += box(x, 218-i*8, 101, 104, fill="#102238", color="#6e624c", radius=8)
    for y in [232, 253, 274]:
        body += f'<path d="M79 {y}h59" stroke="#a0b6cb" stroke-width="3" stroke-linecap="round"/>'
    body += trace("M165 263H265", GOLD, still, .03, .32)
    body += box(269, 245, 62, 54, color=GOLD, fill="#302b25", radius=9)
    shackle = '<path d="M282 245v-17a18 18 0 0 1 36 0v17" fill="none" stroke="#dfbd86" stroke-width="4"/>'
    if not still:
        shackle = '<g><animateTransform attributeName="transform" type="translate" values="0 -8;0 -8;0 0;0 0;0 -8" keyTimes="0;.22;.32;.9;1" dur="8s" repeatCount="indefinite"/>' + shackle + '</g>'
    body += shackle
    body += '<circle cx="300" cy="268" r="5" fill="#dfbd86"/><path d="M300 272v9" stroke="#dfbd86" stroke-width="4"/>'
    body += trace("M334 263H445", GOLD, still, .36, .68)
    store = box(451, 209, 101, 111, color=GOLD)
    store += '<path d="M451 240h101M451 280h101" stroke="#6e624c"/>'
    store += centered("S3", 501, 271, 28, INK, 650)
    store += '<circle cx="533" cy="298" r="5" fill="#98d8c0"/>'
    body += reveal(store, still, .6)
    body += centered("Files", 106, 350, 22, INK, 600)
    body += centered("Encrypt", 300, 350, 22, INK, 600)
    body += centered("Store", 501, 350, 22, INK, 600)
    body += label("AES-256-GCM before upload.", 32, 391, 23)
    (OUT / ("readme-card-s3" + ("-static" if still else "") + ".svg")).write_text(svg(600, 420, "Files are encrypted with AES-256-GCM before upload to S3-compatible storage.", body), encoding="utf-8")


def handbook(mobile, still):
    entries = [
        ("01 / SET UP", "Connect & collect.", ["Accounts. Collection. Proxies.", "Start with a dedicated account."], BLUE),
        ("02 / WORK A CASE", "Follow the connections.", ["Investigations. Export & verify.", "Independent witness."], GOLD),
        ("03 / MAINTAIN", "Keep it running.", ["Server, Docker and recovery.", "Troubleshooting."], STEEL),
    ]
    width, height = (640, 660) if mobile else (1200, 220)
    result = ""
    for index, (kicker, title, lines, color) in enumerate(entries):
        x, y = (0, index*230) if mobile else (index*408, 0)
        if mobile:
            # Keep the same reading order with larger type on a narrow screen.
            body = card(640, 200, kicker, title, lines, color, still=still, delay=index)
            body = body.replace('font-size="13"', 'font-size="18"').replace('font-size="27"', 'font-size="34"').replace('font-size="17"', 'font-size="25"')
            body = body.replace('y="145"', 'y="136"')
        else:
            body = card(384, 220, kicker, title, lines, color, still=still, delay=index)
        result += f'<g transform="translate({x} {y})">{body}</g>'
        if index < 2:
            route = f'M320 {y+201}V{y+229}' if mobile else f'M{x+385} 110H{x+407}'
            result += f'<path d="{route}" stroke="#3b526a" stroke-width="2"/>'
    name = "readme-handbook" + ("-mobile" if mobile else "") + ("-static" if still else "")
    title = "Set up: accounts, collection and proxies. Work a case: investigations, exports and verification. Maintain: server, Docker, recovery and troubleshooting."
    (OUT / (name + ".svg")).write_text(svg(width, height, title, result), encoding="utf-8")


BUTTONS = (
    ("access", "ACCESS", "PERMISSIONS", BUTTON_BLUE, 70, 117),
    ("routes", "PROXIES", "IP MODES", BUTTON_STEEL, 79, 89),
    ("apprise", "APPRISE", "SETUP", BUTTON_BLUE, 70, 58),
    ("s3", "S3", "SETUP & RECOVERY", BUTTON_GOLD, 36, 138),
    ("backup", "BACKUP", "GUIDE", BUTTON_STEEL, 67, 58),
    ("accounts", "SET UP", "ACCOUNTS", BUTTON_BLUE, 64, 88),
    ("investigate", "INVESTIGATE", "GUIDE", BUTTON_GOLD, 105, 58),
    ("maintain", "MAINTAIN", "SERVER & DOCKER", BUTTON_STEEL, 86, 137),
    ("wiki", "WIKI", "OPEN", BUTTON_BLUE, 47, 51),
    ("offline", "HANDBOOK", "OFFLINE", BUTTON_STEEL, 91, 75),
    ("docs", "DOCS", "REFERENCE", BUTTON_STEEL, 51, 97),
    ("explain", "EVIDENCE", "EXPLORE", BUTTON_BLUE, 83, 80),
    ("model", "MODEL", "REFERENCE", BUTTON_STEEL, 63, 97),
    ("project", "BY", "PHISHDESTROY", BUTTON_GOLD, 31, 119),
    ("contribute", "CODE", "CONTRIBUTE", BUTTON_BLUE, 51, 105),
    ("support", "HELP", "SUPPORT", BUTTON_BLUE, 48, 80),
    ("security", "SECURITY", "REPORT", BUTTON_GOLD, 82, 71),
)


def buttons():
    for name, left, right, color, a, b in BUTTONS:
        width = a+b
        body = (f'<clipPath id="edge"><rect width="{width}" height="34" rx="4"/></clipPath>'
                f'<g clip-path="url(#edge)"><rect width="{a}" height="34" fill="#16293d"/>'
                f'<rect x="{a}" width="{b}" height="34" fill="{color}"/>'
                f'<path d="M0 1H{width}" stroke="#fff" opacity=".12"/></g>'
                '<g fill="#fff" font-size="11" font-weight="600" letter-spacing=".7" text-anchor="middle">'
                f'<text x="{a/2}" y="21">{escape(left)}</text><text x="{a+b/2}" y="21">{escape(right)}</text></g>')
        (OUT / ("readme-button-" + name + ".svg")).write_text(svg(width, 34, left + ": " + right, body), encoding="utf-8")


def divider(still):
    body = f'''<defs><linearGradient id="line" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="1200" y2="0"><stop stop-color="{BLUE}" stop-opacity="0"/><stop offset=".35" stop-color="{BLUE}" stop-opacity=".7"/><stop offset=".5" stop-color="{GOLD}"/><stop offset=".65" stop-color="{BLUE}" stop-opacity=".7"/><stop offset="1" stop-color="{BLUE}" stop-opacity="0"/></linearGradient></defs>
<path d="M0 14H566M634 14H1200" stroke="url(#line)" stroke-width="1.5"/>
<path d="M580 14L588 6L596 14L588 22Z" fill="none" stroke="{BLUE}" opacity=".55"/>
<path d="M597 14L605 6L613 14L605 22Z" fill="{GOLD}">'''
    if not still:body += '<animate attributeName="opacity" values=".4;1;.4" dur="3s" repeatCount="indefinite"/>'
    body += f'</path><path d="M614 14L622 6L630 14L622 22Z" fill="none" stroke="{BLUE}" opacity=".55"/>'
    for x, end, color in [(140, 460, BLUE), (1060, 740, BLUE)]:
        body += f'<circle cx="{x}" cy="14" r="2" fill="{color}">'
        if not still:body += f'<animate attributeName="cx" values="{x};{end};{x}" dur="6s" repeatCount="indefinite"/>'
        body += '</circle>'
    (OUT / ("readme-divider" + ("-static" if still else "") + ".svg")).write_text(svg(1200, 28, "Section divider", body), encoding="utf-8")


def outline_captions(font_path):
    from fontTools.pens.svgPathPen import SVGPathPen
    from fontTools.ttLib import TTFont
    from fontTools.varLib.instancer import instantiateVariableFont

    ns = "http://www.w3.org/2000/svg"
    ET.register_namespace("", ns)
    faces = {w: instantiateVariableFont(TTFont(font_path), {"wght": w}, inplace=False) for w in (400, 600, 650)}
    cache = {}
    files = [*OUT.glob("readme-card-*.svg"), *OUT.glob("readme-feature-*.svg"), *OUT.glob("readme-handbook*.svg"), *OUT.glob("readme-button-*.svg")]
    for path in files:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
        definitions = ET.Element("{" + ns + "}defs")
        glyph_ids = {}

        def visit(parent, inherited):
            inherited = {**inherited, **parent.attrib}
            for index, node in enumerate(list(parent)):
                attrs = {**inherited, **node.attrib}
                if node.tag != "{" + ns + "}text":
                    visit(node, inherited)
                    continue
                value = "".join(node.itertext())
                weight = int(attrs.get("font-weight", 400))
                face = faces[weight]
                size = float(attrs.get("font-size", 16))
                scale = size / face["head"].unitsPerEm
                spacing = float(attrs.get("letter-spacing", 0))
                glyph_set, cmap = face.getGlyphSet(), face.getBestCmap()
                chars = []
                for char in value:
                    key = weight, char
                    if key not in cache:
                        glyph = glyph_set[cmap[ord(char)]]
                        pen = SVGPathPen(glyph_set)
                        glyph.draw(pen)
                        cache[key] = pen.getCommands(), glyph.width
                    commands, width = cache[key]
                    if key not in glyph_ids and commands:
                        glyph_ids[key] = "caption-" + str(len(glyph_ids))
                        ET.SubElement(definitions, "{" + ns + "}path", {"id": glyph_ids[key], "d": commands})
                    chars.append((glyph_ids.get(key), width))
                length = sum(width * scale + spacing for _, width in chars) - spacing
                x, y = float(attrs.get("x", 0)), float(attrs.get("y", 0))
                if attrs.get("text-anchor") == "middle":x -= length / 2
                group = ET.Element("{" + ns + "}g", {"aria-label": value, "fill": attrs.get("fill", "#fff"), "transform": f"translate({x:g} {y:g}) scale({scale:g} {-scale:g})"})
                offset = 0
                for ident, width in chars:
                    if ident:
                        ET.SubElement(group, "{" + ns + "}use", {"href": "#" + ident, "transform": f"translate({offset:g} 0)"})
                    offset += width + spacing / scale
                parent.remove(node)
                parent.insert(index, group)

        visit(root, {})
        root.insert(1, definitions)
        path.write_text(ET.tostring(root, encoding="unicode"), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", required=True, help="Path to the OFL-licensed Manrope variable TTF")
    args = parser.parse_args()
    buttons()
    for still in (False, True):
        features(still)
        services(still)
        divider(still)
        for mobile in (False, True):handbook(mobile, still)
    outline_captions(args.font)
    feature_layouts()
    service_layouts()
    print("Rendered service cards, handbook routes, compact buttons and dividers in the TgWitness palette.")


if __name__ == "__main__":
    main()
