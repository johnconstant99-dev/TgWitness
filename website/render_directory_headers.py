import argparse
from pathlib import Path

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_readme import Drawing


INK, MUTED, BLUE, GOLD, GREEN = "#edf5f9", "#9db3c3", "#8acbf4", "#e5bf83", "#a3d9c3"
SECTIONS = {
    "docs": ("Documentation", "Guides, procedures and technical reference", "01", BLUE),
    "source": ("Application", "The collector, the record and the workspace", "02", BLUE),
    "capture": ("Independent capture", "Recorders, controls and verification", "03", GREEN),
    "deploy": ("Deployment", "Installers, containers and background services", "04", GOLD),
    "tools": ("Build & verify", "Development tools and reproducible checks", "05", BLUE),
    "website": ("The public website", "Documentation, guides and the interactive demo", "06", GREEN),
    "integrations": ("Integrations", "Connect the archive to your workflow", "07", GREEN),
    "examples": ("Working examples", "Readable configurations to start from", "08", GOLD),
    "languages": ("Languages", "Interface strings, guides and translated pages", "09", "#c5b9e4"),
    "github": ("Project workflow", "Contributions, checks and publication", "10", BLUE),
    "assets": ("Visual assets", "Screenshots, diagrams and project artwork", "11", GOLD),
}


def art_defs(d, still):
    d.add('''<defs>
<linearGradient id="card-paper" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#f0f5f3"/><stop offset="1" stop-color="#c2d4dc"/></linearGradient>
<linearGradient id="card-dark" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#1b3547"/><stop offset="1" stop-color="#102332"/></linearGradient>
<linearGradient id="scan-wash" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#8acbf4" stop-opacity="0"/><stop offset="1" stop-color="#8acbf4" stop-opacity=".16"/></linearGradient>
<filter id="card-shadow" x="-.25" y="-.25" width="1.6" height="1.7"><feDropShadow dx="0" dy="12" stdDeviation="10" flood-color="#02070d" flood-opacity=".35"/></filter>
</defs>''')
    if not still:
        d.add('''<style>
.float-a{animation:float-a 9s ease-in-out infinite}.float-b{animation:float-b 9s ease-in-out infinite}
.draw{stroke-dasharray:1;animation:draw 9s ease-in-out infinite}
.live{animation:live 3s ease-in-out infinite}
@keyframes float-a{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
@keyframes float-b{0%,100%{transform:translateY(-4px)}50%{transform:translateY(5px)}}
@keyframes draw{0%,8%{stroke-dashoffset:1;opacity:.2}38%,82%{stroke-dashoffset:0;opacity:1}100%{stroke-dashoffset:0;opacity:.2}}
@keyframes live{0%,100%{opacity:.4}50%{opacity:1}}
</style>''')


def box(d, x, y, width, height, fill="url(#card-dark)", stroke="#456377", radius=12):
    d.add(f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="{radius}" fill="{fill}" stroke="{stroke}"/>')


def line(d, path, color="#507084", width=1.5, extra=""):
    d.add(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linecap="round" stroke-linejoin="round" {extra}/>')


def label(d, text, x, y, size=12, color=MUTED, weight=600):
    d.text(text, x, y, size, color, weight)


def check(d, x, y, color=GREEN, size=1):
    line(d, f"m{x} {y} {5*size} {5*size} {11*size} {-13*size}", color, 2.2, 'class="draw" pathLength="1"')


def badge(d, text, x, y, width, color=GREEN):
    box(d, x, y, width, 24, "#112c32", "#3c5f63", 12)
    d.add(f'<circle cx="{x+12}" cy="{y+12}" r="2.5" fill="{color}" class="live"/>')
    label(d, text, x+21, y+16, 9, color)


def route(d, path, still, color=BLUE, delay=0):
    line(d, path, "#446477", 1.5, 'stroke-dasharray="3 6"')
    if not still:
        d.add(f'<circle r="3.5" fill="{color}"><animateMotion path="{path}" dur="5s" begin="{delay}s" repeatCount="indefinite"/></circle>')


def evidence_scene(d, x, y, scale, still):
    d.add(f'<g transform="translate({x} {y}) scale({scale})">')
    d.add('<g transform="rotate(4 326 185)">')
    box(d, 162, 30, 334, 294, "#102636", "#395a70")
    d.add('</g><g filter="url(#card-shadow)">')
    box(d, 146, 25, 334, 294)
    label(d, "SIGNED OBSERVATION JOURNAL", 167, 54, 12, INK)
    label(d, "SHA-256  /  ED25519", 167, 77, 10, GREEN)
    line(d, "M166 92h293", "#476377", 1)
    line(d, "M177 124V262", "#456477", 2)
    for index, (yy, title, link, color) in enumerate((
            (102, "Message observed", "h1  /  previous: h0", BLUE),
            (171, "Edit preserved", "h2  /  previous: h1", GOLD),
            (240, "Deletion recorded", "h3  /  previous: h2", GREEN))):
        box(d, 194, yy, 265, 58, "#0c2130", "#355369", 7)
        d.add(f'<circle cx="177" cy="{yy+23}" r="5" fill="#102636" stroke="{color}" stroke-width="2"/>')
        label(d, title, 208, yy+23, 17, INK)
        label(d, link, 208, yy+44, 11, color)
        if not still:
            d.add(f'<rect x="194" y="{yy}" width="265" height="58" rx="7" fill="{color}" opacity="0"><animate attributeName="opacity" values="0;.16;.16;0;0" keyTimes="0;.06;.22;.3;1" dur="12s" begin="{-12+index*2}s" repeatCount="indefinite"/></rect>')
    d.add('</g>')
    route(d, "M14 124H162", still, BLUE, -1)
    d.add('<g class="float-a" filter="url(#card-shadow)">')
    box(d, 4, 93, 113, 73, "url(#card-paper)", "#d8e6eb", 9)
    label(d, "TELEGRAM", 17, 117, 11, "#355265")
    line(d, "M18 132h70m-70 12h48", "#7b97a9", 3)
    d.add('</g>')
    route(d, "M177 193H91V283", still, GOLD, -3)
    d.add('<g class="float-b" filter="url(#card-shadow)">')
    box(d, 9, 271, 177, 98, "url(#card-paper)", "#d8e6eb", 9)
    label(d, "CHECKPOINT", 25, 296, 12, "#284b62")
    label(d, "count: 2 / head: h2", 25, 321, 13, "#284b62")
    label(d, "Kept separately", 25, 349, 11, "#516d7e")
    d.add('</g>')
    route(d, "M330 319V355H453", still, GREEN, -2)
    d.add('<g class="float-a" filter="url(#card-shadow)">')
    box(d, 370, 330, 211, 67, "#173b3c", "#6ca592", 10)
    label(d, "EVIDENCE.ZIP", 388, 355, 14, INK)
    label(d, "Check with a trusted key", 388, 378, 11, GREEN)
    check(d, 548, 354, GREEN, 1)
    d.add('</g>')
    label(d, "RETAIN THE CHAIN. VERIFY THE HANDOFF.", 102, 429, 11, MUTED)
    d.add('</g>')


def illustration(d, section, still, accent):
    if section in {"docs", "examples"}:
        d.add('<g class="float-b"><g transform="rotate(-9 180 120)">')
        box(d, 115, 22, 191, 204, "#172f41", "#476377")
        d.add('</g></g><g class="float-a" filter="url(#card-shadow)">')
        box(d, 99, 14, 190, 208, "url(#card-paper)", "#d0e1e8")
        label(d, "FIELD GUIDE" if section == "docs" else "CONFIGURATION", 118, 47, 11, "#405d71")
        line(d, "M118 62h151", "#a7bdc9", 1)
        if section == "docs":
            for i, (title, length) in enumerate((("Start", 117), ("Collect", 98), ("Verify", 128))):
                yy = 88+i*43
                label(d, f"0{i+1}", 118, yy, 10, "#688193")
                label(d, title, 142, yy, 16, "#18364b")
                line(d, f"M142 {yy+11}h{length-18}", "#9ab2c1", 2)
            d.add('<path d="M250 14v37l10-6 10 6V14" fill="#b59462"/>')
        else:
            label(d, "{", 119, 96, 30, "#36596f")
            label(d, "}", 119, 189, 30, "#36596f")
            for i, length in enumerate((98, 122, 81)):
                yy = 94+i*28
                line(d, f"M146 {yy}h{length}", "#7a98aa", 5)
                line(d, f"M146 {yy}h30", "#305d75", 5, 'class="draw" pathLength="1"')
        d.add('</g>')
        route(d, "M39 172C69 172 58 105 99 105", still, accent)
        box(d, 19, 141, 61, 58, "#183348", "#547b94", 10)
        label(d, "Aa" if section == "docs" else "{ }", 31, 178, 25, INK)
        badge(d, "REFERENCE" if section == "docs" else "READY", 226, 195, 115, accent)
    elif section == "integrations":
        route(d, "M140 129H176V67H225", still, accent)
        route(d, "M140 129H176V197H225", still, accent, -2)
        for xx, yy, text in ((20, 90, "WORKSPACE"), (225, 28, "MCP"), (225, 158, "WEBHOOK")):
            d.add('<g class="float-a" filter="url(#card-shadow)">')
            box(d, xx, yy, 112, 78)
            line(d, f"M{xx+17} {yy+21}h22m-22 9h14", accent, 2)
            label(d, text, xx+14, yy+57, 10, INK)
            d.add('</g>')
        label(d, "SCOPED READS / OUTGOING EVENTS", 36, 258, 10, MUTED)
    elif section in {"source", "github"}:
        names = {"source": ("COLLECT", "JOURNAL", "PANEL"), "github": ("REVIEW", "CHECKS", "PUBLISH")}[section]
        for path, delay in (("M103 61C165 61 127 120 179 120", -1), ("M179 120C234 120 207 181 258 181", -3)):
            route(d, path, still, accent, delay)
        for i, (xx, yy, text) in enumerate(zip((17, 126, 235), (24, 83, 144), names)):
            d.add(f'<g class="float-{chr(97+i%2)}" filter="url(#card-shadow)">')
            box(d, xx, yy, 112, 78)
            d.add(f'<rect x="{xx+14}" y="{yy+13}" width="22" height="20" rx="5" fill="{accent}" fill-opacity=".15"/>')
            if i == 2:
                check(d, xx+17, yy+22, accent, .7)
            else:
                line(d, f"M{xx+19} {yy+19}h12m-12 6h8", accent, 1.5)
            label(d, text, xx+14, yy+57, 11, INK)
            d.add('</g>')
        label(d, "OBSERVE / PRESERVE / CONNECT" if section != "github" else "REVIEWED SOURCE / CHECKED BUILD", 23, 244, 9, MUTED)
    elif section == "deploy":
        for i, yy in enumerate((31, 96, 161)):
            d.add(f'<g class="float-{chr(97+i%2)}" filter="url(#card-shadow)">')
            box(d, 82+i*9, yy, 222, 49, radius=7)
            label(d, ("BUILD", "INSTALL", "RUN")[i], 104+i*9, yy+30, 12, INK)
            line(d, f"M{225+i*9} {yy+18}h25m-25 10h25", "#5f788a", 2)
            d.add(f'<circle class="live" cx="{282+i*9}" cy="{yy+24}" r="4" fill="{accent}"/>')
            d.add('</g>')
        route(d, "M62 50H35V185H82", still, accent, -2)
        badge(d, "CHECKED BUILD", 176, 225, 142, GREEN)
    elif section in {"capture", "website", "tools"}:
        d.add('<g class="float-b" filter="url(#card-shadow)">')
        box(d, 35, 25, 285, 185)
        for xx in (50, 61, 72):
            d.add(f'<circle cx="{xx}" cy="40" r="2" fill="#7393a8"/>')
        line(d, "M36 53h283", "#3d5b70", 1)
        if section == "capture":
            box(d, 56, 73, 166, 43, "#213f51", "#385b70", 7)
            box(d, 104, 128, 194, 40, "#264d56", "#48757c", 7)
            line(d, "M69 90h111m-111 12h75M118 144h144m-144 12h96", "#a0bfcc", 3)
            if not still:
                d.add('<g><animateTransform attributeName="transform" type="translate" values="0 0;0 112;0 112;0 0" keyTimes="0;.55;.85;1" dur="7s" repeatCount="indefinite"/><rect x="47" y="56" width="260" height="28" fill="url(#scan-wash)"/><path d="M47 84h260" stroke="#b5e6da" stroke-width="1.5"/></g>')
            line(d, "M45 82V64h18m246 18V64h-18M45 178v18h18m246-18v18h-18", accent, 2)
        elif section == "website":
            box(d, 51, 68, 72, 125, "#0d2231", "#345367", 5)
            for yy, length in ((87, 42), (107, 33), (127, 40), (147, 27)):
                line(d, f"M64 {yy}h{length}", "#63879e", 3)
            box(d, 137, 68, 167, 62, "#264b5a", "#4b7886", 5)
            label(d, "DEMO", 151, 106, 22, INK)
            for xx in (137, 224):
                box(d, xx, 143, 80, 50, "#142d40", "#3c5e74", 5)
                line(d, f"M{xx+12} 160h43m-43 14h28", "#7f9caf", 3)
        else:
            label(d, ">_", 55, 85, 20, accent)
            label(d, "VERIFY ARCHIVE", 92, 84, 12, INK)
            for i, text in enumerate(("JOURNAL", "FILES", "CHECKPOINT")):
                yy = 114+i*30
                label(d, text, 58, yy, 11, MUTED)
                check(d, 270, yy-5, GREEN, .8)
                line(d, f"M162 {yy-4}h82", "#426278", 2)
        d.add('</g><g class="float-a">')
        box(d, 208, 185, 136, 48, "url(#card-paper)", "#d8e6e9", 9)
        label(d, "CAPTURED" if section == "capture" else "EXPLORE" if section == "website" else "VERIFIED", 224, 214, 12, "#24485b")
        check(d, 315, 207, "#366a63", .8)
        d.add('</g>')
    elif section == "languages":
        for xx, yy, angle, text, code in ((37, 50, -12, "Aa", "EN"), (147, 28, 6, "Aa", "FR"), (231, 100, 13, "Aa", "DE")):
            d.add(f'<g class="float-a"><g transform="rotate({angle} {xx+51} {yy+59})" filter="url(#card-shadow)">')
            box(d, xx, yy, 102, 126, "url(#card-paper)", "#d7e5e8")
            label(d, code, xx+15, yy+24, 11, "#6b607e")
            label(d, text, xx+12, yy+83, 42, "#393e58", 700)
            d.add('</g></g>')
        d.add('<circle cx="183" cy="197" r="39" fill="#152d41" stroke="#8d85ad"/>')
        d.add('<ellipse cx="183" cy="197" rx="17" ry="39" fill="none" stroke="#aba1c4"/>')
        line(d, "M144 197h78m-70-19h62m-62 38h62", "#aba1c4", 1)
        route(d, "M108 217C126 251 232 257 267 214", still, accent, -2)
    else:
        d.add('<g transform="rotate(-9 180 128)">')
        box(d, 51, 48, 245, 151, "#17364a", "#406981")
        d.add('</g><g class="float-a" filter="url(#card-shadow)">')
        box(d, 65, 33, 245, 164, "url(#card-paper)", "#dce8ea")
        box(d, 77, 45, 221, 140, "#18384c", "none", 7)
        d.add(f'<circle cx="253" cy="82" r="19" fill="{accent}"/>')
        d.add('<path d="m77 171 58-75 59 62 39-38 65 65H77Z" fill="#345d72"/><path d="m77 181 58-64 60 68H77Z" fill="#6a97a9"/>')
        line(d, "M77 171l58-75 59 62 39-38 65 65", "#bdd5de", 2, 'class="draw" pathLength="1"')
        d.add('</g>')
        line(d, "M49 65V18h48m229 148v47h-48", accent, 1.5)
        badge(d, "PROJECT ARTWORK", 147, 214, 166, accent)


def render(font, section, mobile, still):
    title, subtitle, number, accent = SECTIONS[section]
    width, height = (640, 480) if mobile else (1200, 340)
    d = Drawing(font, width, height, "TgWitness / " + title)
    art_defs(d, still)
    d.add(f'''<defs>
<linearGradient id="surface" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#0c1c2a"/><stop offset="1" stop-color="#07131d"/></linearGradient>
<radialGradient id="ambient"><stop stop-color="{accent}" stop-opacity=".15"/><stop offset="1" stop-color="{accent}" stop-opacity="0"/></radialGradient>
<pattern id="grid" width="28" height="28" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".65" fill="#8eafc4" opacity=".16"/></pattern>
<clipPath id="frame"><rect x="1" y="1" width="{width-2}" height="{height-2}" rx="16"/></clipPath>
</defs>
<rect x="1" y="1" width="{width-2}" height="{height-2}" rx="16" fill="url(#surface)" stroke="#3d5668"/>
<g clip-path="url(#frame)"><rect width="{width}" height="{height}" fill="url(#grid)"/><ellipse cx="{width*.8}" cy="{height*.48}" rx="380" ry="280" fill="url(#ambient)"/></g>''')
    line(d, "M36 1h100", accent, 2)
    d.text("PHISHDESTROY / TGWITNESS", 36, 42, 11, accent, 600, 1.5)
    if mobile:
        d.text(title, 33, 109, 42 if len(title)<18 else 38, INK, 700, -1)
        subtitles = {
            "docs": ("Guides, procedures", "and technical reference"),
            "source": ("The collector, the record", "and the workspace"),
            "capture": ("Recorders, controls", "and verification"),
            "deploy": ("Installers, containers", "and background services"),
            "tools": ("Development tools", "and reproducible checks"),
            "website": ("Documentation, guides", "and the interactive demo"),
            "integrations": ("Connect the archive", "to your workflow"),
            "examples": ("Readable configurations", "to start from"),
            "languages": ("Interface strings, guides", "and translated pages"),
            "github": ("Contributions, checks", "and publication"),
            "assets": ("Screenshots, diagrams", "and project artwork"),
        }
        for yy, text in zip((145, 171), subtitles[section]):
            label(d, text, 36, yy, 19, MUTED, 500)
        d.add('<g transform="translate(135 190) scale(.96)">')
    else:
        d.text(title, 33, 137, 49 if len(title)<18 else 45, INK, 700, -1.5)
        label(d, subtitle, 36, 181, 21, MUTED, 500)
        d.text(number, 36, 255, 36, accent, 500, -1)
        label(d, "REPOSITORY GUIDE", 96, 251, 10, MUTED)
        d.add('<g transform="translate(773 35)">')
    illustration(d, section, still, accent)
    d.add('</g>')
    line(d, f"M36 {height-39}H{width-36}", "#334d60", 1)
    label(d, "TGWITNESS / " + section.upper(), 36, height-16, 9, MUTED)
    label(d, number, width-49, height-16, 10, accent)
    suffix = ("-mobile" if mobile else "") + ("-static" if still else "")
    description = "Static illustration for reduced motion." if still else "Animated editorial illustration; static and mobile variants are available."
    d.write(f"section-{section}{suffix}.svg", subtitle + ". " + description + " Illustrative workflow, not live status.")


def main():
    parser = argparse.ArgumentParser(description="Render the repository's directory covers.")
    parser.add_argument("--font", type=Path, required=True)
    args = parser.parse_args()
    font = {weight: instantiateVariableFont(TTFont(args.font), {"wght": weight}) for weight in (500, 600, 700)}
    for section in SECTIONS:
        for mobile in (False, True):
            for still in (False, True):
                render(font, section, mobile, still)
    print(f"Rendered {len(SECTIONS) * 4} directory covers.")


if __name__ == "__main__":
    main()
