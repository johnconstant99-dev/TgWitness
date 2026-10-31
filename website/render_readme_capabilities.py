"""Build the animated README capability cards. Uses the existing Manrope font."""
import argparse

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_case_assets import save
from render_readme import Drawing

BLUE, GOLD, GREEN = "#8ccfff", "#dfbd86", "#98d8c0"
INK, MUTED = "#edf5fc", "#a0b6cb"


def box(d, x, y, width, height, color="#39546a", fill="#102238"):
    d.add(f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="9" '
          f'fill="{fill}" stroke="{color}"/>')


def route(d, path, color, still):
    d.add(f'<path d="{path}" fill="none" stroke="#39546a" stroke-width="2"/>')
    if not still:
        d.add(f'<path class="signal" d="{path}" fill="none" stroke="{color}" '
              'stroke-width="3" stroke-dasharray="12 90">'
              '<animate attributeName="stroke-dashoffset" from="0" to="-204" dur="5s" repeatCount="indefinite"/></path>')


def card(d, index, mobile, still):
    x, y = (0, index * 306) if mobile else (index % 2 * 612, index // 2 * 306)
    color = (GOLD, BLUE, BLUE, GOLD)[index]
    headings = (
        ("PEOPLE & DOSSIERS", "New name. Same trail.", "Names, replies and shared leads across chats."),
        ("BOT INVESTIGATION", "Record every step.", "Supported button presses become signed receipts."),
        ("SEARCH, AI & MCP", "Ask. Check the source.", "Review saved records. Share read-only access."),
        ("SEALED CLOUD MODE", "Make the collector auditable.", "Pinned code. Provider records. Tunnel access."),
    )
    kicker, title, detail = headings[index]
    d.add(f'<g transform="translate({x} {y})">')
    box(d, 1, 1, 586, 288, fill="url(#surface)")
    d.add(f'<path d="M25 1H563" stroke="{color}" stroke-opacity=".65"/>')
    d.text(kicker, 26, 34, 12, color, 600, 1.6)
    d.text(title, 26, 77, 30, INK, 700, -.6)
    d.text(detail, 26, 107, 17, MUTED, 500)
    if index == 0:
        for xx, name in [(26, "@old_name"), (351, "@new_name")]:
            box(d, xx, 147, 209, 47, color="#6e624c")
            d.text(name, xx + 17, 178, 21, INK, 600)
        route(d, "M236 170H350", color, still)
        d.add(f'<path d="m339 164 9 6-9 6" fill="none" stroke="{color}" stroke-width="2"/>')
        d.text("ONE TELEGRAM ID", 26, 233, 12, color, 600, 1)
        d.text("Open the records behind each connection.", 26, 264, 18, INK, 500)
    elif index == 1:
        for xx, title, sub in [(26, "Preview", "Save the link"), (209, "Interact", "Press a button"), (392, "Journal", "Keep the result")]:
            box(d, xx, 148, 169, 68)
            d.text(title, xx + 14, 176, 20, INK, 600)
            d.text(sub, xx + 14, 200, 14, MUTED, 500)
        route(d, "M195 181H209M378 181H392", color, still)
        d.text("Requests and results stay together.", 26, 264, 18, INK, 500)
    elif index == 2:
        box(d, 26, 146, 535, 45)
        d.add(f'<circle cx="49" cy="166" r="7" fill="none" stroke="{color}" stroke-width="2"/>'
              f'<path d="m54 171 6 6" stroke="{color}" stroke-width="2"/>')
        d.text("Where did this link appear?", 73, 175, 21, INK, 500)
        for xx, title in [(26, "Chat A / #146"), (300, "Chat B / #205")]:
            box(d, xx, 205, 261, 33)
            d.text(title, xx + 14, 228, 16, color, 600)
        if not still:
            d.add('<rect class="scan" x="27" y="147" width="3" height="43" fill="#8ccfff" opacity=".3">'
                  '<animateTransform attributeName="transform" type="translate" values="0 0;530 0;0 0" dur="7s" repeatCount="indefinite"/></rect>')
        d.text("Source references travel with the answer.", 26, 264, 18, INK, 500)
    else:
        for xx, title, sub in [(26, "Firewall", "No inbound rules"), (209, "Collector", "SSH masked"), (392, "Tunnel", "Panel access")]:
            box(d, xx, 148, 169, 68, color="#6e624c")
            d.text(title, xx + 14, 176, 20, INK, 600)
            d.text(sub, xx + 14, 200, 14, MUTED, 500)
        route(d, "M378 181H392", color, still)
        d.text("Inspect the deployment, not just its output.", 26, 264, 18, INK, 500)
    d.add('</g>')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", required=True)
    args = parser.parse_args()
    fonts = {weight: instantiateVariableFont(TTFont(args.font), {"wght": weight}, inplace=True)
             for weight in (500, 600, 700)}
    for mobile in (False, True):
        for still in (False, True):
            d = Drawing(fonts, 588 if mobile else 1200, 1208 if mobile else 596,
                        "People, bot interactions, archive analysis and sealed deployment")
            d.add('<defs><linearGradient id="surface" x2="1" y2="1">'
                  '<stop stop-color="#0c1c2e"/><stop offset="1" stop-color="#070f1b"/>'
                  '</linearGradient></defs>')
            for index in range(4):
                card(d, index, mobile, still)
            name = "readme-capabilities" + ("-mobile" if mobile else "") + ("-static" if still else "") + ".svg"
            save(d, name, "Illustrated workflows with fictional identities and record references. "
                 "People profiles, signed interaction receipts, source-linked analysis and auditable cloud deployment.")


if __name__ == "__main__":
    main()
