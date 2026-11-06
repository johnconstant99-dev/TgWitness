import argparse
from pathlib import Path

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_readme import Drawing


SECTIONS = {
    "docs": ("Documentation", "Guides, procedures and technical reference", "01", "#abc8e5"),
    "source": ("Application", "The collector, the record and the workspace", "02", "#9ebfdf"),
    "capture": ("Independent capture", "Recorders, controls and verification", "03", "#9dcbbf"),
    "deploy": ("Deployment", "Installers, containers and background services", "04", "#d9be91"),
    "tools": ("Build & verify", "Development tools and reproducible checks", "05", "#abc8e5"),
    "website": ("The public website", "Documentation, guides and the interactive demo", "06", "#a7c9c4"),
    "integrations": ("Integrations", "Connect the archive to your workflow", "07", "#9dcbbf"),
    "examples": ("Working examples", "Readable configurations to start from", "08", "#d9be91"),
    "languages": ("Languages", "Interface strings, guides and translated pages", "09", "#bdb5d9"),
    "github": ("Project workflow", "Contributions, checks and publication", "10", "#abc8e5"),
    "assets": ("Visual assets", "Screenshots, diagrams and project artwork", "11", "#d9be91"),
}


def illustration(d, section, x, y, accent, still):
    d.add(f'<g transform="translate({x} {y})" fill="none" stroke="{accent}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">')
    if section in {"docs", "examples", "languages"}:
        d.add('<path d="M30 14h100l24 24v112H30Z" fill="#142331"/><path d="M130 14v24h24M44 46h59M44 65h94M44 82h79M44 99h94M44 116h62"/><path d="M18 29v134h121" stroke-opacity=".35"/>')
        if section == "examples":
            d.add('<path d="m173 68-13 14 13 14m22-28 13 14-13 14m-10-34-6 39"/>')
        elif section == "languages":
            d.add('<circle cx="180" cy="109" r="27" fill="#0c1924"/><ellipse cx="180" cy="109" rx="12" ry="27"/><path d="M153 109h54m-50-13h46m-46 26h46"/>')
        else:
            d.add('<path d="M119 14v46l10-6 10 6V23" fill="#243647"/>')
    elif section == "deploy":
        for yy in (20, 68, 116):
            d.add(f'<rect x="22" y="{yy}" width="168" height="35" rx="4" fill="#142331"/><circle cx="41" cy="{yy+17}" r="3" fill="{accent}"/><path d="M58 {yy+17}h61m34-5h19m-19 10h19"/>')
        d.add('<path d="M106 55v13m0 35v13"/>')
    elif section in {"capture", "assets", "website"}:
        d.add('<rect x="17" y="30" width="184" height="111" rx="5" fill="#142331"/><path d="M17 52h184" stroke-opacity=".5"/><circle cx="29" cy="41" r="1.5"/><circle cx="37" cy="41" r="1.5"/>')
        if section == "capture":
            d.add('<path d="M44 82V69h15m115 13V69h-15M44 111v13h15m115-13v13h-15"/><circle cx="109" cy="96" r="14"/><circle cx="109" cy="96" r="4" fill="' + accent + '"/>')
        elif section == "assets":
            d.add('<circle cx="153" cy="78" r="8"/><path d="m35 123 40-46 31 31 22-18 52 33Z"/>')
        else:
            d.add('<path d="M33 68h47v56H33Zm61 0h90M94 82h68m-68 14h90m-90 14h82m-82 14h59"/>')
        d.add('<path d="M70 156h78m-65-15v15m52-15v15" stroke-opacity=".5"/>')
    elif section in {"source", "integrations", "github"}:
        d.add('<path d="M106 48v29m0 31v24M51 92h40m30 0h42" stroke-opacity=".5"/>')
        for xx, yy, ww, hh in ((70, 16, 72, 32), (17, 77, 34, 31), (163, 77, 34, 31), (70, 132, 72, 32)):
            d.add(f'<rect x="{xx}" y="{yy}" width="{ww}" height="{hh}" rx="4" fill="#142331"/>')
        d.add('<rect x="91" y="77" width="30" height="31" rx="4" fill="#243647"/><path d="M83 28h46m-46 8h29M83 144h46m-46 8h29"/>')
        if section == "github":
            d.add('<path d="m98 93 5 5 11-13"/>')
        else:
            d.add('<path d="M101 87h10v10h-10Z"/>')
    else:
        d.add('<rect x="17" y="24" width="184" height="130" rx="5" fill="#142331"/><path d="M17 46h184m-167-11h18" stroke-opacity=".5"/><path d="m45 72 16 13-16 13m30 0h40"/><path d="m125 127 13 12 30-37"/>')
    if still:
        d.add('</g>')
        return
    d.add('<g stroke="#e4f0f7" stroke-width="2.5">')
    if section in {"docs", "examples", "languages"}:
        for index, (yy, length) in enumerate(((65, 94), (82, 79), (99, 94))):
            d.add(f'<path class="flow" pathLength="1" style="animation-delay:{index * .35}s" d="M44 {yy}h{length}"/>')
    elif section == "deploy":
        for index, yy in enumerate((37, 85, 133)):
            d.add(f'<circle class="signal" style="animation-delay:{index * .7}s" cx="41" cy="{yy}" r="5"/>')
    elif section == "capture":
        d.add('<circle class="pulse" cx="109" cy="96" r="22"/>')
    elif section == "assets":
        d.add('<path class="flow" pathLength="1" d="m35 123 40-46 31 31 22-18 52 33"/>')
    elif section == "website":
        for index, yy in enumerate((68, 96, 124)):
            d.add(f'<path class="flow" pathLength="1" style="animation-delay:{index * .4}s" d="M94 {yy}h59"/>')
    elif section in {"source", "integrations", "github"}:
        d.add('<path class="flow" pathLength="1" d="M106 48v29m0 31v24"/><path class="flow" pathLength="1" style="animation-delay:1s" d="M51 92h40m30 0h42"/>')
    else:
        d.add('<path class="flow" pathLength="1" d="m125 127 13 12 30-37"/>')
    d.add('</g>')
    d.add('</g>')


def render(font, section, mobile, still):
    title, subtitle, number, accent = SECTIONS[section]
    width, height = (640, 260) if mobile else (1200, 240)
    d = Drawing(font, width, height, "TgWitness / " + title)
    if not still:
        d.add('''<style>
.flow,.signal,.pulse{opacity:0}
.flow{stroke-dasharray:1;stroke-dashoffset:1;animation:trace 7s ease-in-out infinite}
.signal{animation:signal 7s ease-in-out infinite}
.pulse{transform-origin:109px 96px;animation:pulse 7s ease-out infinite}
@keyframes trace{0%,10%{stroke-dashoffset:1;opacity:0}20%{opacity:.8}55%,65%{stroke-dashoffset:0;opacity:.8}85%,100%{stroke-dashoffset:0;opacity:0}}
@keyframes signal{0%,15%,70%,100%{opacity:0}35%,45%{opacity:.7}}
@keyframes pulse{0%,10%{transform:scale(.65);opacity:0}25%{opacity:.65}65%,100%{transform:scale(1.45);opacity:0}}
</style>''')
    d.add(f'<rect x=".5" y=".5" width="{width-1}" height="{height-1}" rx="10" fill="#0c1721" stroke="#344655"/>')
    d.add(f'<path d="M34 0h52" stroke="{accent}" stroke-width="3"/>')
    d.text("PHISHDESTROY / TGWITNESS", 34, 41, 12, accent, 600, 1.5)
    if mobile:
        d.text(title, 32, 117, 40 if len(title) < 18 else 36, "#f0f4f7", 700, -1)
        subtitle_lines = {
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
        for yy, line in zip((155, 182), subtitle_lines[section]):
            d.text(line, 34, yy, 19, "#b5c3cf", 500)
        d.add('<g transform="translate(418 79) scale(.76)">')
        illustration(d, section, 0, 0, accent, still)
        d.add('</g>')
    else:
        d.text(title, 31, 119, 49, "#f0f4f7", 700, -1.4)
        d.text(subtitle, 34, 157, 20, "#b5c3cf", 500)
        d.add('<path d="M857 41v145" stroke="#2c3d4b"/>')
        illustration(d, section, 911, 17, accent, still)
    d.add(f'<path d="M34 {height-39}H{width-34}" stroke="#2c3d4b"/>')
    d.text("REPOSITORY GUIDE", 34, height-16, 10, "#a3b3c0", 600, 1.5)
    d.text(number, width-51, height-16, 11, accent, 600)
    suffix = ("-mobile" if mobile else "") + ("-static" if still else "")
    description = ". Static illustration for reduced motion." if still else ". Subtle illustration animation. A static version is available."
    d.write(f"section-{section}{suffix}.svg", subtitle + description + " No external resources.")


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
