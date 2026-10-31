"""Compose TgWitness's investigation artwork into its repository identity.

Pass --font /path/to/Manrope.ttf. Uses the existing, reviewed illustration and
outlined type. No network, new image generation, account data or SVG scripts.
"""
import argparse
from copy import deepcopy
from math import ceil
from pathlib import Path
import re
import tomllib
import xml.etree.ElementTree as ET

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_readme import Drawing
from render_case_assets import save

ROOT = Path(__file__).resolve().parents[1]
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)


def scene():
    source = ET.fromstring((ROOT / "docs/assets/presentation/readme-investigation-animated.svg").read_text(encoding="utf-8"))
    result = []
    for element in source:
        tag = element.tag.rsplit("}", 1)[-1]
        cls = element.get("class", "")
        keep = tag in {"defs", "style"} or (tag == "use" and bool(element.get("mask")))
        keep |= cls.startswith(("source-", "packet ")) or bool(element.get("clip-path"))
        if not keep:
            continue
        item = deepcopy(element)
        if cls.startswith("source-"):

            for child in list(item):
                if child.tag.rsplit("}", 1)[-1] == "g":
                    item.remove(child)
        result.append(ET.tostring(item, encoding="unicode"))
    svg = "".join(result)
    svg = re.sub(r'id="([^"]+)"', r'id="scene-\1"', svg)
    svg = re.sub(r'href="#([^"]+)"', r'href="#scene-\1"', svg)
    svg = re.sub(r'url\(#([^)]+)\)', r'url(#scene-\1)', svg)
    return svg


def background(d):
    d.add('''<defs>
<linearGradient id="identity-bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#080f1a"/><stop offset=".55" stop-color="#0c1829"/><stop offset="1" stop-color="#10243a"/></linearGradient>
<radialGradient id="identity-light"><stop stop-color="#4084b7" stop-opacity=".26"/><stop offset="1" stop-color="#1e507e" stop-opacity="0"/></radialGradient>
<linearGradient id="identity-line"><stop stop-color="#69b9f8" stop-opacity="0"/><stop offset=".5" stop-color="#c7ebff"/><stop offset="1" stop-color="#d9b97f" stop-opacity="0"/></linearGradient>
<radialGradient id="identity-fade" cx="52%" cy="52%" r="64%"><stop offset=".55" stop-color="white"/><stop offset="1" stop-color="black"/></radialGradient>
<mask id="identity-feather"><rect width="820" height="690" fill="url(#identity-fade)"/></mask>
<linearGradient id="identity-fade-y" x1="0" y1="0" x2="0" y2="1"><stop stop-color="black"/><stop offset=".1" stop-color="white"/><stop offset=".83" stop-color="white"/><stop offset="1" stop-color="black"/></linearGradient>
<mask id="identity-vertical"><rect width="820" height="690" fill="url(#identity-fade-y)"/></mask>
<pattern id="identity-dots" width="28" height="28" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".8" fill="#88b2d3" opacity=".14"/></pattern>
</defs>''')
    d.add(f'<rect width="{d.width}" height="{d.height}" rx="22" fill="url(#identity-bg)"/>')
    d.add(f'<rect width="{d.width}" height="{d.height}" rx="22" fill="url(#identity-dots)"/>')
    d.add(f'<ellipse cx="{d.width*.72}" cy="{d.height*.48}" rx="500" ry="430" fill="url(#identity-light)"/>')
    d.add('''<style>
.identity-orbit{transform-box:fill-box;transform-origin:center;animation:identity-orbit 48s linear infinite}
.identity-float{animation:identity-float 12s ease-in-out infinite}
.identity-trace{stroke-dasharray:100 1300;animation:identity-trace 12s linear infinite}
.identity-sign{stroke-dasharray:1;animation:identity-sign 12s ease-in-out infinite}
@keyframes identity-orbit{to{transform:rotate(360deg)}}
@keyframes identity-float{0%,100%{transform:translateY(0)}50%{transform:translateY(-11px)}}
@keyframes identity-trace{from{stroke-dashoffset:1400}to{stroke-dashoffset:0}}
@keyframes identity-sign{0%,35%{stroke-dashoffset:1;opacity:.3}65%,90%{stroke-dashoffset:0;opacity:1}100%{stroke-dashoffset:0;opacity:.3}}
</style>''')


def artwork(d, x, y, width, height, original):
    d.add(f'<svg x="{x}" y="{y}" width="{width}" height="{height}" viewBox="0 0 820 690">'
          '<g mask="url(#identity-vertical)"><g mask="url(#identity-feather)"><g class="identity-float">'
          '<svg width="820" height="690" viewBox="535 30 820 690">'
          + original + '</svg></g></g></g></svg>')


def hero(font, original, mobile=False, still=False, wiki=False):
    width, height = (720, 920) if mobile else (1440, 690)
    if wiki and not mobile:
        height = 510
    d = Drawing(font, width, height, "TgWitness — Follow the trail. Preserve the evidence.")
    background(d)
    if mobile:
        artwork(d, -40, 241, 800, 665, original)
    else:
        d.add('<circle class="identity-orbit" cx="1070" cy="335" r="291" fill="none" '
              'stroke="#8abfdf" stroke-opacity=".17" stroke-dasharray="95 370 20 180" stroke-width="1.5"/>')
        artwork(d, 624 if not wiki else 790, -9 if not wiki else -30, 840 if not wiki else 650, 705 if not wiki else 547, original)
    mark = (ROOT / "tgwitness/static/mark.svg").read_text(encoding="utf-8")
    mark = mark.replace('viewBox="0 0 48 48"', 'x="44" y="37" width="34" height="34" viewBox="0 0 48 48"')
    d.add(mark)
    d.text("TgWitness / PHISHDESTROY" if wiki else "PHISHDESTROY", 91, 60, 13, "#b9cde1", 600, 2.4)
    if mobile:
        d.text("TgWitness", 41, 175, 98, "#edf6ff", 800, -3.5)
        d.text("Follow the trail.", 45, 233, 36, "#e3effd", 600, -.8)
        d.text("Preserve the evidence.", 45, 281, 36, "#9fc7ef", 600, -.8)
        d.add('<path d="M0 840H720V898a22 22 0 0 1-22 22H22a22 22 0 0 1-22-22Z" fill="#0b1828" fill-opacity=".9"/>'
              '<path d="M46 840H674" stroke="#365472"/>')
        d.text("CAPTURE", 46, 881, 15, "#a9c8e4", 600, 1.6)
        d.text("CONNECT", 280, 881, 15, "#a9c8e4", 600, 1.6)
        d.text("VERIFY", 537, 881, 15, "#d8c29a", 600, 1.6)
        d.add('<path class="identity-trace" d="M46 840H674" fill="none" stroke="url(#identity-line)" stroke-width="2"/>')
    elif wiki:
        d.text("THE INVESTIGATION HANDBOOK", 46, 117, 13, "#9fc7ef", 600, 2)
        d.text("Work the case.", 43, 218, 76, "#edf6ff", 800, -2.5)
        d.text("Keep the record.", 43, 303, 76, "#a5cff7", 800, -2.5)
        d.text("Your first capture. Your next lead. Your signed handoff.", 47, 365, 21, "#b3c7dd")
        d.add('<path d="M46 451H1394" stroke="#29455f"/>')
        d.add('<path class="identity-trace" d="M46 451H1394" fill="none" stroke="url(#identity-line)" stroke-width="2"/>')
    else:
        d.text("YOUR TELEGRAM INVESTIGATION WORKSPACE", 47, 127, 13, "#92b9d9", 600, 1.2)
        d.text("TgWitness", 40, 247, 116, "#edf6ff", 800, -4)
        d.text("Follow the trail.", 47, 320, 43, "#e3effd", 600, -1.2)
        d.text("Preserve the evidence.", 47, 377, 43, "#9fc7ef", 600, -1.2)
        d.text("Conversations. Connections. A record you can verify.", 49, 432, 20, "#adc2d9")
        d.add('<path class="identity-sign" pathLength="1" d="M53 520c27-61 41-54 25-5s38-60 47-39-42 69-13 61 47-49 46-27-17 32 4 21 18-36 31-19-8 30 9 22l68-20" '
              'fill="none" stroke="#b9dfd5" stroke-width="2.2" stroke-linecap="round"/>')
        d.text("FOLLOW THE SOURCES. KEEP THE CONTEXT.", 49, 578, 13, "#799ab7", 600, 1.1)
        d.add('<path d="M0 630H1440V668a22 22 0 0 1-22 22H22a22 22 0 0 1-22-22Z" fill="#0b1828" fill-opacity=".9"/>'
              '<path d="M46 631H1394" stroke="#29455f"/>')
        d.add('<path class="identity-trace" d="M46 631H1394" fill="none" stroke="url(#identity-line)" stroke-width="2"/>')
        for x, num, word in [(47,"01","CAPTURE"),(360,"02","CONNECT"),(719,"03","PRESERVE"),(1091,"04","VERIFY")]:
            d.text(num, x, 665, 12, "#d4b884", 600)
            d.text(word, x+34, 665, 12, "#a3bfd9", 600, 1.6)
    if still:
        d.add('<style>*{animation:none!important}.packet,.scan,.seal-ring{display:none}.flow{opacity:.45}.identity-sign{stroke-dasharray:none;stroke-dashoffset:0}</style>')
    else:


        d.add('''<style>
.source-private,.source-group,.source-channel,.source-bot,.source-record{opacity:1;animation:identity-source 8s ease-in-out infinite}
.source-group{animation-delay:-2s}.source-channel{animation-delay:-4s}.source-bot{animation-delay:-6s}
@keyframes identity-source{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}
</style>''')
    name = "identity-wiki" if wiki else "identity-hero"
    name += "-mobile" if mobile else ""
    name += "-static" if still else ""
    save(d, name + ".svg", "An illustrated investigation: sources connect, observed records move into a dossier, "
         "and a signature is drawn. Fictional records, not a screenshot of the application.")


def setup_actions(font, still=False, navigation=False):
    """Two-line action buttons from the PhishDestroy repository family."""
    actions = (
        ("setup", "SETUP GUIDE", "Install, launch & capture", "#a7d7ff"),
        ("account", "DEDICATED ACCOUNT", "Prepare your Telegram account", "#b9d8d0"),
        ("deploy", "DOCKER & SERVERS", "Deploy your workspace", "#dcc294"),
    )
    if navigation:
        actions = (
            ("demo", "EXPLORE THE WORKSPACE", "Fictional demonstration records", "#a7d7ff"),
            ("start", "START YOUR FIRST CASE", "Install, launch & capture", "#b9d8d0"),
            ("wiki", "OPEN THE HANDBOOK", "The investigation handbook", "#dcc294"),
        )
    icons = {
        "setup": '<path d="M17 19h7q4 0 4 4v18q0-4-4-4h-7Zm22 0h-7q-4 0-4 4v18q0-4 4-4h7Z"/>'
                 '<path class="detail" d="M20 25h4m-4 5h4m8-5h4m-4 5h4"/>',
        "account": '<path d="m28 17 11 4v9c0 7-11 12-11 12S17 37 17 30v-9Z"/>'
                   '<circle class="detail" cx="28" cy="26" r="3"/>'
                   '<path d="M23 35c0-6 10-6 10 0"/>',
        "deploy": '<rect x="17" y="18" width="22" height="10" rx="2"/>'
                  '<rect x="17" y="32" width="22" height="10" rx="2"/>'
                  '<path d="M27 23h8m-8 14h8"/>'
                  '<circle class="detail" cx="22" cy="23" r="1"/>'
                  '<circle class="detail" cx="22" cy="37" r="1"/>',
        "demo": '<rect x="16" y="18" width="24" height="20" rx="3"/>'
                '<path d="M24 43h8m-4-5v5"/><path class="detail" d="m25 23 7 5-7 5Z"/>',
        "start": '<path d="M20 20h14a3 3 0 0 1 3 3v14a3 3 0 0 1-3 3H20a3 3 0 0 1-3-3V23a3 3 0 0 1 3-3Z"/>'
                 '<path class="detail" d="m23 30 3 3 7-8"/>',
    }
    icons["wiki"] = icons["setup"]
    for index, (name, title, subtitle, accent) in enumerate(actions):
        d = Drawing(font, 248, 64, title + ": " + subtitle)
        top, bottom = ("#23486d", "#142d46") if name == "demo" else ("#14263b", "#0c1829")
        d.add(f'''<defs>
<linearGradient id="button-bg" x2="1" y2="1"><stop stop-color="{top}"/><stop offset="1" stop-color="{bottom}"/></linearGradient>
<linearGradient id="button-rim"><stop stop-color="{accent}" stop-opacity=".12"/><stop offset=".5" stop-color="{accent}" stop-opacity=".85"/><stop offset="1" stop-color="{accent}" stop-opacity=".12"/></linearGradient>
<linearGradient id="button-light"><stop stop-color="{accent}" stop-opacity="0"/><stop offset=".5" stop-color="{accent}" stop-opacity=".07"/><stop offset="1" stop-color="{accent}" stop-opacity="0"/></linearGradient>
<clipPath id="button-clip"><rect x="1" y="1" width="246" height="62" rx="7"/></clipPath>
</defs>
<rect x=".5" y=".5" width="247" height="63" rx="8" fill="url(#button-bg)" stroke="#3c536c"/>
<rect class="rim" x=".75" y=".75" width="246.5" height="62.5" rx="8" fill="none" stroke="url(#button-rim)" opacity=".5"/>
<g clip-path="url(#button-clip)"><path class="sheen" d="M-80 1h65L5 63h-65Z" fill="url(#button-light)"/></g>
<path d="M17 1h36" stroke="{accent}" stroke-opacity=".85"/>
<g fill="none" stroke="{accent}" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">{icons[name]}</g>''')
        d.text(title, 50, 27, 11.5, "#e7f2ff", 800, .2)
        d.text(subtitle, 50, 46, 10.4, "#adc1d6", 500)
        d.add(f'<path class="arrow" d="m229 26 5 6-5 6" fill="none" stroke="{accent}" '
              'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>')
        if not still:
            delay = -index * 2
            d.add(f'''<style>
.rim{{animation:rim 6s ease-in-out {delay}s infinite}}
.arrow{{animation:arrow 6s ease-in-out {delay}s infinite}}
.detail{{animation:detail 6s ease-in-out {delay}s infinite}}
.sheen{{animation:sheen 9s ease-in-out {delay}s infinite}}
@keyframes rim{{0%,100%{{opacity:.25}}50%{{opacity:.9}}}}
@keyframes arrow{{0%,100%{{transform:translateX(0)}}50%{{transform:translateX(3px)}}}}
@keyframes detail{{0%,100%{{opacity:.55}}50%{{opacity:1}}}}
@keyframes sheen{{0%{{transform:translateX(0)}}45%,100%{{transform:translateX(350px)}}}}
</style>''')
        suffix = "-static" if still else ""
        prefix = "identity-nav-" if navigation else "identity-action-"
        save(d, prefix + name + suffix + ".svg", title + ": " + subtitle)


def separator(font, still=False):
    d = Drawing(font, 1200, 30, "Section divider")
    d.add('''<defs>
<linearGradient id="left" gradientUnits="userSpaceOnUse" x1="0" y1="15" x2="550" y2="15"><stop stop-color="#7db9e6" stop-opacity="0"/><stop offset="1" stop-color="#c9ab77" stop-opacity=".7"/></linearGradient>
<linearGradient id="right" gradientUnits="userSpaceOnUse" x1="650" y1="15" x2="1200" y2="15"><stop stop-color="#c9ab77" stop-opacity=".7"/><stop offset="1" stop-color="#7db9e6" stop-opacity="0"/></linearGradient>
</defs>
<path d="M0 15H550" stroke="url(#left)"/><path d="M650 15H1200" stroke="url(#right)"/>
<path class="trace" d="M0 15H550" fill="none" stroke="url(#left)" stroke-width="2" stroke-dasharray="34 516"/>
<path class="trace" d="M650 15H1200" fill="none" stroke="url(#right)" stroke-width="2" stroke-dasharray="34 516"/>
<path class="pulse" d="m600 10 5 5-5 5-5-5Z" fill="#d1b47f"/>
<g fill="#93bad8" opacity=".45"><circle cx="569" cy="15" r="1.8"/><circle cx="582" cy="15" r="1.8"/><circle cx="618" cy="15" r="1.8"/><circle cx="631" cy="15" r="1.8"/></g>''')
    if not still:
        d.add('''<style>.trace{animation:trace 9s linear infinite}.pulse{animation:pulse 6s ease-in-out infinite}
@keyframes trace{to{stroke-dashoffset:-550}}@keyframes pulse{0%,100%{opacity:.45}50%{opacity:1}}</style>''')
    save(d, "identity-divider" + ("-static" if still else "") + ".svg", "Decorative section divider")


def metadata(font):
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    panel_languages = {"en", *(path.stem for path in (ROOT / "tgwitness/locales").glob("*.json"))}
    guide_languages = panel_languages | {path.stem for path in (ROOT / "tgwitness/guide_locales").glob("*.json") if path.stem != "keys"}
    labels = (
        ("version", f"v{version} · pre-release", "#a7d7ff", "#16304a"),
        ("verification", "Tested environments", "#b9d8d0", "#16312f"),
        ("languages", f"{len(panel_languages)} interface languages · {len(guide_languages)} guide languages", "#becbe4", "#252a40"),
        ("license", "MIT", "#dcc294", "#332b1d"),
    )
    face = font[600]
    glyphs, cmap = face.getGlyphSet(), face.getBestCmap()
    for name, label, ink, fill in labels:
        width = ceil(sum(glyphs[cmap[ord(c)]].width for c in label) / face['head'].unitsPerEm * 11.5) + 40
        d = Drawing(font, width, 30, label)
        d.add(f'<rect x=".5" y=".5" width="{width-1}" height="29" rx="4" fill="{fill}" stroke="{ink}" stroke-opacity=".25"/>'
              f'<circle cx="13" cy="15" r="2" fill="{ink}"/>')
        d.text(label, 23, 19, 11.5, ink, 600)
        save(d, "identity-meta-" + name + ".svg", label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", required=True)
    args = parser.parse_args()
    font = {weight: instantiateVariableFont(TTFont(args.font), {"wght":weight}, inplace=False) for weight in (500,600,800)}
    original = scene()
    for still in (False, True):
        hero(font, original, still=still)
        hero(font, original, mobile=True, still=still)
        hero(font, original, wiki=True, still=still)
        setup_actions(font, still=still)
        setup_actions(font, still=still, navigation=True)
        separator(font, still=still)
    metadata(font)
    print("Rendered identity covers, navigation and setup buttons, section dividers and metadata badges.")


if __name__ == "__main__":
    main()
