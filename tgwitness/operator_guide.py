"""An offline operations card written next to the managed launcher."""
import base64
import hashlib
import html
import os
import shlex
from pathlib import Path

from . import __version__

REPOSITORY = "https://github.com/phishdestroy/TgWitness"
MARKER = "TgWitness managed operator guide v1"
SCRIPT = """document.querySelectorAll('button[data-copy]').forEach(button=>button.addEventListener('click',async()=>{
const code=button.parentElement.querySelector('code');try{await navigator.clipboard.writeText(code.textContent);button.textContent='Copied';}
catch{const range=document.createRange();range.selectNodeContents(code);const selection=getSelection();selection.removeAllRanges();selection.addRange(range);button.textContent='Selected: copy with Ctrl/Cmd+C';}
setTimeout(()=>button.textContent='Copy',2500);}));"""
STYLE = """*{box-sizing:border-box}html{color-scheme:light dark;scroll-behavior:smooth}body{margin:0;background:#f4f6fa;color:#192233;font:16px/1.6 system-ui,sans-serif}main{max-width:1080px;margin:auto;padding:38px 24px 64px}a{color:#2359c5;text-underline-offset:4px}header{padding:24px 0 32px;border-bottom:1px solid #d8dfea}.brand{font-weight:750;letter-spacing:-.04em;font-size:24px}h1{font-size:clamp(30px,5vw,52px);line-height:1.12;letter-spacing:-.04em;margin:20px 0 12px}h2{font-size:23px;line-height:1.25;margin:0 0 12px}h3{font-size:16px;margin:20px 0 7px}p{margin:8px 0}.muted{color:#536079}.badge{font-size:12px;border:1px solid #c5d5ef;padding:5px 9px;border-radius:20px}.links,nav{display:flex;flex-wrap:wrap;gap:10px 20px;margin:18px 0}nav a{font-size:14px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:28px 0}.card{background:#fff;border:1px solid #d8dfea;border-radius:16px;padding:24px;scroll-margin-top:16px}.wide{grid-column:1/-1}.command{position:relative;background:#edf1f7;border-radius:9px;padding:13px;margin:10px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;padding-right:62px;font-size:13px;line-height:1.65}code{font-family:ui-monospace,Consolas,monospace}button{cursor:pointer;position:absolute;right:8px;top:8px;background:#fff;color:#2359c5;border:1px solid #c5d5ef;border-radius:6px;padding:7px;font:inherit;font-size:12px}button:focus-visible,a:focus-visible{outline:3px solid #639bff;outline-offset:3px}.note{border-left:3px solid #6795df;padding-left:14px;margin:18px 0;font-size:14px}.location{overflow-wrap:anywhere;font-size:14px}footer{border-top:1px solid #d8dfea;padding-top:20px;font-size:14px}@media(max-width:680px){.grid{grid-template-columns:1fr}.card{padding:20px}main{padding:20px 16px}}@media(prefers-color-scheme:dark){body{background:#111823;color:#e5ebf5}.card{background:#172130;border-color:#2c3b50}.muted{color:#afbed2}.command{background:#0e1725}button{background:#1b2b42;border-color:#425e87;color:#a9cbff}a{color:#9ec5ff}header,footer{border-color:#2c3b50}.badge{border-color:#425e87}}@media print{body,.card,.command{background:white;color:black}button,nav{display:none}main{padding:0}.grid{display:block}.card{break-inside:avoid;margin:18px 0}a{color:black}}"""


def content(root, windows=None):
    windows = os.name == "nt" if windows is None else windows
    launcher = str(root / "bin" / ("tgwitness.cmd" if windows else "tgwitness"))
    call = "& '" + launcher.replace("'", "''") + "'" if windows else shlex.quote(launcher)
    sections = [
        ("daily", "Open and check", [
            ("Open the panel", "Shows the current address and access key. Keep the key private.", call + " open"),
            ("Check the installation", "Print the actual program and data locations. A root systemd installation keeps private data under /var/lib; /opt/tgwitness contains the program.", call + " paths"),
            ("Read this guide in a terminal", "No browser or network connection is needed.", call + " guide --print"),
        ]),
        ("access", "Control access", [
            ("Replace the administrator key", "Requires a running panel. Ends all current browser sessions. Issued colleague tokens remain valid; revoke them separately under Access. Also available in Access → My limits.", call + " token rotate"),
            ("Give a colleague their own token", "In Access, choose Reviewer or Analyst, selected chats, an expiry and sign-in limits. Use one allowed sign-in for a token that can start only one session. End sessions or revoke access from the same page.", None),
            ("Operator privacy", "Full browser User-Agent strings are not retained. IP addresses are masked in the panel process log. Address checks still use real client IPs; signed access records and local service logs can contain them.", None),
        ]),
        ("scope", "Choose what gets recorded", [
            ("Leave out your own messages", "Sources → Observation scope → turn off Own actions, then save. This affects ongoing observation and automatic rechecks. Explicit actions and manually requested history snapshots remain recorded.", None),
            ("Exclude a chat", "Sources → Exclude. Review Excluded chats before choosing the whole account. Previously saved records are kept.", None),
            ("Share less", "Use a disclosure copy to remove selected identities or files from a supported account export. Review the preview and final file. Keep the original signed archive separately; editing it invalidates its signatures.", None),
        ]),
    ]
    if not windows:
        sections.insert(1, ("tunnel", "Temporary HTTPS link", [
            ("Close the public tunnel", "For a managed trycloudflare.com panel. The local panel and collection keep running. The tunnel stays off after a service restart.", call + " tunnel off"),
            ("Create a new public link", "Starts a new tunnel connection. Use the address printed by Open; the old address is no longer the active route.", call + " tunnel restart\n" + call + " open"),
            ("Enable the tunnel again", "Public access is restored explicitly. The panel access key is still required.", call + " tunnel on"),
            ("Stop everything", "Stops the panel, tunnel and collection. Saved data stays. Observation pauses until you start again.", call + " stop\n# Start again when ready:\n" + call + " start"),
        ]))
        sections.append(("maintenance", "Update and troubleshoot", [
            ("Apply an update", "Run the installer again with the same installation directory, then restart. A restart briefly pauses collection. Back up the data directory before an update.", "curl -fsSL https://get.destroy.tools/install.sh | TGWITNESS_INSTALL_DIR=" + shlex.quote(str(root)) + " bash -s -- --no-start\n" + call + " restart"),
            ("Status, diagnosis and service logs", "Service logs are local diagnostics and may contain addresses. Review them before sharing.", call + " status\n" + call + " doctor\n" + call + " logs"),
            ("Private access over SSH", "With the public tunnel off, run this on your own computer. Replace USER and SERVER with your SSH login, and use the panel port from panel.json. Then open http://127.0.0.1:8787 and enter your panel key.", "ssh -N -L 8787:127.0.0.1:8787 USER@SERVER"),
        ]))
    else:
        sections.append(("maintenance", "Update and troubleshoot", [
            ("Stop and start", "The Windows panel runs in its terminal window. Press Ctrl+C there to stop it; run the launcher again to start. Closing your browser only locks access and does not stop collection.", call + " open"),
            ("Update", "Close the running panel, run the installer again with the same InstallDir, then open your launcher. Your data folder is retained.", "$env:TGWITNESS_INSTALL_DIR='" + str(root).replace("'", "''") + "'\nirm https://get.destroy.tools/install.ps1 | iex"),
        ]))
    restriction = None
    if not windows:
        from .panelctl import service_name
        restriction = "sudo systemctl edit " + service_name(Path(root).resolve())
    sections.append(("ip", "Limit who can connect", [
        ("IP restrictions", "For a colleague: Access → Allowed addresses, or bind to the first sign-in. Check the address shown in Open sessions first. These settings do not restrict the administrator key.", None),
        ("Restrict the whole panel", "TGWITNESS_PANEL_ALLOWED_IPS accepts comma-separated IPs or CIDR networks and covers administrator access too. The example includes loopback for local CLI recovery. Keep SSH open; remove this environment setting and restart to undo it. For a user service, use systemctl --user edit without sudo.", restriction),
        *([] if windows else [
            ("Paste into the service editor", "Replace 203.0.113.10 with your real client IP. This is service configuration, not a shell command. Save and close the editor.", '[Service]\nEnvironment="TGWITNESS_PANEL_ALLOWED_IPS=127.0.0.1/32,::1/128,203.0.113.10/32"'),
            ("Apply the address restriction", "Run after saving the service configuration. This restarts collection briefly; saved evidence stays.", call + " restart"),
        ]),
        ("Proxy trust", "Forwarded client addresses are accepted only from explicitly trusted proxy peers. The managed quick tunnel trusts its local cloudflared connector; the domain setup trusts its local Caddy proxy. Custom deployments set TGWITNESS_TRUSTED_PROXIES and TGWITNESS_PROXY_HEADER. Never trust every source address.", None),
        ("A stable address or another login layer", "A named Cloudflare Tunnel with Access, or a configured HTTPS reverse proxy, can add an access policy in front of the panel. A temporary quick-tunnel URL is not an access policy. Keep TgWitness authentication enabled.", None),
    ]))
    return sections


def write(root, windows=None):
    from .panelctl import atomic
    root = Path(root).resolve()
    for name in ('START-HERE.html', 'START-HERE.txt'):
        path = root / name
        if path.is_symlink() or (path.exists() and MARKER not in path.read_text(encoding='utf-8')[:512]):
            raise ValueError('Refusing to replace an unrelated operator guide: ' + str(path))
    sections = content(root, windows)
    esc = html.escape
    text = [MARKER, "TgWitness " + __version__ + " | Operator guide", "Program: " + str(root), REPOSITORY, ""]
    cards = []
    for anchor, title, rows in sections:
        text.extend([title.upper(), ""])
        body = []
        for heading, explanation, command in rows:
            text.extend([heading, explanation, *( [command] if command else []), ""])
            body.append("<h3>" + esc(heading) + "</h3><p>" + esc(explanation) + "</p>")
            if command:
                body.append('<div class="command"><pre><code>' + esc(command) + '</code></pre><button type="button" data-copy>Copy</button></div>')
        cards.append('<section class="card" id="' + anchor + '"><h2>' + esc(title) + "</h2>" + "".join(body) + "</section>")
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    page = ('<!doctype html><!-- ' + MARKER + ' --><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
            "style-src 'unsafe-inline'; script-src 'sha256-" + script_hash + "'; base-uri 'none'; form-action 'none'\">"
            '<title>TgWitness · Your operator guide</title><style>' + STYLE + '</style></head><body><main><header>'
            '<div class="brand">TgWitness <span class="badge">Local operator guide · ' + esc(__version__) + '</span></div>'
            '<h1>Your workspace.<br>Your controls.</h1><p class="muted">The everyday commands for access, collection and recovery. Available offline, beside your software.</p>'
            '<p class="location">Installed in <code>' + esc(str(root)) + '</code></p><div class="links"><a href="' + REPOSITORY + '">Repository ↗</a>'
            '<a href="' + REPOSITORY + '/blob/main/docs/ACCESS.md">Access guide ↗</a><a href="' + REPOSITORY + '/blob/main/docs/OPERATIONS.md">Operations ↗</a>'
            '<a href="' + REPOSITORY + '/issues">Help &amp; issues ↗</a></div></header><nav aria-label="Guide sections">' +
            ''.join('<a href="#' + anchor + '">' + esc(title) + '</a>' for anchor, title, _ in sections) + '</nav>'
            '<p class="note">Run commands on the machine where TgWitness is installed, using the account that installed it. Commands below use your full launcher path.</p>'
            '<div class="grid">' + ''.join(cards) + '</div><footer>This file contains no access keys or account credentials. '
            'Keep the data directory and backups private. <a href="' + REPOSITORY + '/blob/main/docs/SECURITY-MODEL.md">Trust model</a></footer>'
            '</main><script>' + SCRIPT + '</script></body></html>')
    atomic(root / "START-HERE.html", page, 0o644)
    atomic(root / "START-HERE.txt", "\n".join(text) + "\n", 0o644)
    return root / "START-HERE.html"
