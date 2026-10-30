"""Render compact, responsive chapter covers in the TgWitness casework style."""
import argparse
import textwrap

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_casework import BLUE, GOLD, INK, MUTED, canvas
from render_case_assets import save


CHAPTERS = {
    "Getting-Started": ("01 / START HERE", "Your first capture.", "Install, explore the demo and connect your workspace."),
    "Accounts": ("01 / CONNECT AND CAPTURE", "Connect your workspace.", "Choose an account, sign in and confirm its identity."),
    "Proxies": ("01 / CONNECT AND CAPTURE", "Choose the connection.", "Set the route before connecting your account."),
    "Collection": ("01 / CONNECT AND CAPTURE", "Choose what to preserve.", "Sources, captured changes and coverage."),
    "Chat-Export": ("02 / INVESTIGATE AND EXPORT", "Take the chat with you.", "Visible history, readable offline, in a signed archive."),
    "Investigations": ("02 / INVESTIGATE AND EXPORT", "Follow the connections.", "Search across chats and return to the source records."),
    "Exports-and-Verification": ("02 / INVESTIGATE AND EXPORT", "Hand over the evidence.", "Choose the output. Retain the key. Verify the record."),
    "Independent-Witness": ("03 / INDEPENDENT CHECKS", "Keep an independent check.", "Retained checkpoints and independent witness records."),
    "Server-and-Docker": ("04 / RUN AND PROTECT", "Keep the collector running.", "Persistent storage, server access and controlled updates."),
    "Notifications": ("04 / RUN AND PROTECT", "Keep an eye on the case.", "Problems, chat changes and summaries in your channels."),
    "Off-site-Copy": ("04 / RUN AND PROTECT", "Keep another copy.", "Encrypt locally. Copy to S3. Retain the recovery key."),
    "Backup-and-Recovery": ("04 / RUN AND PROTECT", "Protect the workspace.", "Retain the data, configuration and keys that belong to it."),
    "Troubleshooting": ("05 / FIND AN ANSWER", "Find the cause.", "Check the symptom, follow the record and confirm recovery."),
    "FAQ": ("05 / FIND AN ANSWER", "Straight to the answer.", "Accounts, capture, evidence and everyday operation."),
    "Glossary": ("05 / FIND AN ANSWER", "Know what the terms mean.", "A shared vocabulary for observations and evidence."),
}


def chapter(font, slug, mobile, still):
    section, title, subtitle = CHAPTERS[slug]
    width, height = (640, 254) if mobile else (1200, 216)
    color = GOLD if section.startswith(("02", "03")) else BLUE
    d = canvas(font, width, height, title, still, corners=False)
    d.text(section, 32, 43, 19, color, 600, .8)
    d.text(title, 32, 111, 38 if mobile else 46, INK, 700, -.7)
    for i, line in enumerate(textwrap.wrap(subtitle, 42) if mobile else [subtitle]):
        d.text(line, 32, 158+i*33, 23 if mobile else 25, MUTED, 500)
    if not mobile:
        d.text("TGWITNESS / HANDBOOK", 892, 43, 17, MUTED, 600, .5)
    y = height-24
    path = f"M32 {y}H{width-32}"
    d.add(f'<path d="{path}" stroke="#30495f"/><path d="M32 {y}h64" stroke="{color}" stroke-width="3"/>')
    if not still:
        d.add(f'<circle r="3.5" fill="{color}"><animateMotion path="{path}" dur="8s" repeatCount="indefinite"/></circle>')
    name = "wiki-" + slug.lower() + ("-mobile" if mobile else "") + ("-static" if still else "") + ".svg"
    save(d, name, section + ". " + title + " " + subtitle)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--font", required=True)
    args = p.parse_args()
    font = {w: instantiateVariableFont(TTFont(args.font), {"wght": w}, inplace=False) for w in (500, 600, 700)}
    for slug in CHAPTERS:
        for mobile in (False, True):
            for still in (False, True):
                chapter(font, slug, mobile, still)
    print("Rendered", len(CHAPTERS)*4, "responsive handbook covers.")


if __name__ == "__main__":
    main()
