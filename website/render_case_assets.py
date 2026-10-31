"""Render the investigation presentation's navigation and case-path diagrams.

Uses the retained Manrope font licence and the existing SVG drawing helper.
No network access or application data. Pass --font /path/to/Manrope.ttf.
"""
import argparse
import re

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_readme import Drawing, OUT


def save(drawing, name, description):
    """Share repeated glyph outlines; a tenth of a font unit is subpixel here."""
    drawing.write(name, description)
    target = OUT / name
    svg = target.read_text(encoding="utf-8")

    def compact(match):
        value = re.sub(r"-?\d+\.\d+", lambda m: f"{float(m[0]):.1f}".rstrip("0").rstrip("."), match[1])
        return 'd="' + value + '"'

    svg = re.sub(r'(?<![\w-])d="([^"]+)"', compact, svg)
    glyphs = {}

    def share(match):
        transform, path = match.groups()
        ident = glyphs.setdefault(path, "glyph-" + str(len(glyphs)))
        return f'<use href="#{ident}" transform="{transform}"/>'

    svg = re.sub(r'<path transform="(translate\([^"]+\))" d="([^"]+)"/>', share, svg)
    definitions = '<defs>' + ''.join(f'<path id="{ident}" d="{path}"/>' for path, ident in glyphs.items()) + '</defs>'
    svg = svg.replace('</desc>', '</desc>' + definitions, 1)
    target.write_bytes(svg.encode("utf-8"))


def navigation(font):
    entries = (
        ("demo", "Explore the demo", "OPEN THE WORKSPACE"),
        ("start", "Start your first case", "INSTALL & CONNECT"),
        ("wiki", "Investigation Wiki", "THE FIELD GUIDE"),
        ("evidence", "Understand the proof", "THE EVIDENCE MODEL"),
    )
    for i, (name, title, caption) in enumerate(entries):
        d = Drawing(font, 176, 58, title)
        color = "#17385c" if i == 0 else "#0e1d2e"
        d.add(f'<rect x=".5" y=".5" width="175" height="57" rx="8" fill="{color}" stroke="#365573"/>')
        d.text(caption, 13, 19, 8, "#b8cfe6", 600, .65)
        d.text(title, 13, 41, 13, "#f0f6ff", 600)
        d.add('<path d="M155 16h7m-3-3 3 3-3 3" fill="none" stroke="#e8c28a" stroke-width="1.2"/>')
        save(d, "case-" + name + ".svg", title + ". " + caption.capitalize() + ".")


def route(font, mobile=False, still=False):
    width, height = (640, 506) if mobile else (1200, 210)
    d = Drawing(font, width, height, "From sources to a verifiable handoff")
    d.add('<defs><linearGradient id="bg"><stop stop-color="#102136"/>'
          '<stop offset="1" stop-color="#0a1625"/></linearGradient></defs>'
          f'<rect x=".5" y=".5" width="{width-1}" height="{height-1}" rx="14" fill="url(#bg)" stroke="#2c435b"/>')
    stages = (
        ("01", "Choose the sources", "Chats, folders, accounts", "Capture what you observe."),
        ("02", "Follow the connections", "People, files, shared leads", "Return to the source record."),
        ("03", "Preserve the context", "Versions, files, capture gaps", "Keep the observed history."),
        ("04", "Hand over the evidence", "Signed export + trusted key", "Let a recipient verify it."),
    )
    if mobile:
        d.add('<path d="M39 50V410" stroke="#7d684f" stroke-width="2"/>')
    else:
        d.add('<path d="M40 40H945" stroke="#7d684f" stroke-width="2"/>')
    for i, (num, title, subtitle, caption) in enumerate(stages):
        x, y = (76, 43 + i * 120) if mobile else (26 + i * 295, 82)
        cx, cy = (39, y + 6) if mobile else (x + 14, 40)
        d.add(f'<circle cx="{cx}" cy="{cy}" r="13" fill="#12253b" stroke="#c3a276"/>')
        d.text(num, cx - 7, cy + 4, 10, "#e8c28a", 600)
        d.text(title, x, y + 9, 23 if mobile else 19, "#eaf3ff", 600)
        d.text(subtitle, x, y + 40, 18 if mobile else 15, "#b4cee8")
        d.text(caption, x, y + 68, 16 if mobile else 13, "#91abc5")
        if not still:

            d.add(f'<circle cx="{cx}" cy="{cy}" r="18" fill="none" stroke="#b7e1fc" stroke-width="2" opacity="0">'
                  '<animate attributeName="opacity" values="0;1;0;0" '
                  f'keyTimes="0;.1;.25;1" begin="{i*2}s" dur="8s" repeatCount="indefinite"/></circle>')
    suffix = "-mobile" if mobile else ""
    suffix += "-static" if still else ""
    save(d, "case-path" + suffix + ".svg", "Choose sources, follow connections, preserve context and export signed evidence. "
         "Signatures establish integrity relative to a trusted key, not Telegram origin.")


def mobile_chain(font, still=False):
    d = Drawing(font, 640, 964, "A change adds a record. It does not erase one.")
    d.add('<rect x=".5" y=".5" width="639" height="963" rx="16" fill="#0b1828" stroke="#30475f"/>')
    d.text("THE SIGNED OBSERVATION JOURNAL", 28, 43, 13, "#a4c8e9", 600, .7)
    d.text("A change adds a record.", 28, 91, 32, weight=600)
    d.text("It does not erase one.", 28, 131, 29, "#b8d6f9")
    records = (("01", "message.new", "Meet at 10:00", "previous_hash = 000...000", "h1"),
               ("02", "message.edited", "Meet at 11:00", "previous_hash = h1", "h2"),
               ("03", "message.deleted", "Deletion observed", "previous_hash = h2", "h3"))
    for i, (num, kind, message, previous, digest) in enumerate(records):
        y = 166 + i * 177
        if i:
            d.add(f'<path d="M49 {y-28}v27m-6-7 6 7 6-7" fill="none" stroke="#d1af7c" stroke-width="2"/>')
        d.add('<g>')
        if not still:
            d.add(f'<animate attributeName="opacity" values=".35;1;1;.35" keyTimes="0;.1;.9;1" begin="{i*2}s" dur="12s" repeatCount="indefinite"/>')
        d.add(f'<rect x="28" y="{y}" width="584" height="149" rx="11" fill="#13263b" stroke="#355474"/>'
              f'<circle cx="49" cy="{y+27}" r="11" fill="#0d1c2b" stroke="#c9ab7a"/>')
        d.text(num, 42, y + 31, 10, "#ebca92", 600)
        d.text(kind, 74, y + 34, 21, "#adcee9", 600)
        d.text(message, 48, y + 75, 30, weight=600)
        d.text(previous, 48, y + 113, 20, "#b5c9df")
        d.text(digest + " / signed", 450, y + 113, 19, "#b5e6cf", 600)
        d.add('</g>')
    d.text("Each event includes the preceding hash.", 28, 736, 22, "#b8d6f9", 600)
    d.add('<rect x="28" y="761" width="584" height="132" rx="11" fill="#102a30" stroke="#31544e"/>')
    d.text("h[i] = hex(SHA256(C(e[i])))", 47, 800, 25, "#e0f0ef", 600)
    d.text("s[i] = Sign(sk, unhex(h[i]))", 47, 835, 25, "#e0f0ef", 600)
    d.text("Ed25519 signs the 32 digest bytes.", 47, 870, 19, "#a2c9c1")
    d.text("Verify with an independently trusted key.", 28, 927, 20, "#b5c9df")
    save(d, "case-chain-mobile" + ("-static" if still else "") + ".svg",
         "Illustrative records: new message, captured edit and deletion observation. "
         "Each event includes the preceding hash; SHA-256 hashes canonical JSON, "
         "and Ed25519 signs the raw digest bytes. C denotes canonical encoding. "
         "Signatures do not establish Telegram origin or complete capture.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", required=True)
    args = parser.parse_args()
    font = {weight: instantiateVariableFont(TTFont(args.font), {"wght": weight}, inplace=False)
            for weight in (500, 600)}
    navigation(font)
    for mobile in (False, True):
        for still in (False, True):
            route(font, mobile, still)
    for still in (False, True):
        mobile_chain(font, still)
    print("Rendered four navigation images, four case-path variants and two phone chain diagrams.")


if __name__ == "__main__":
    main()
