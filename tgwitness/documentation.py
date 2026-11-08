import base64
import hashlib
import html
import os
import secrets
from datetime import timedelta, timezone
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import action_protocol
from .store import EVENT_FIELDS, canonical, utcnow

FORMAT = "tgwitness-documentation-v1"
KEYS_FORMAT = "tgwitness-documentation-keys-v1"
KEYS_NAME = "documentation-keys-"
SEAL_INFO = b"tgwitness-documentation-seal-v1/"
INDEX = "documentation.sessions"
PREFIX = "documentation.session."
MAX_SESSIONS = 200
MAX_MARKS = 2000
LABELS = ("important", "conclusion", "question", "decision", "adult", "obscene", "violence", "personal")
HIDING = {"adult": "18+", "obscene": "obscene language", "violence": "violence", "personal": "personal data"}
LABEL_NAMES = {"important": "Important", "conclusion": "Conclusion", "question": "Open question",
               "decision": "Decision and rationale", "adult": "18+",
               "obscene": "Obscene language", "violence": "Violence", "personal": "Personal data"}
LIMITS = (
    "A draft can be paused, restarted or deleted. Only a fixed document is signed and recorded in the journal.",
    "The fixed document lists every step, note and conclusion with its hash. A copy without some of them is "
    "detectable as incomplete.",
    "Content hidden for a stated reason stays in the signed journal; the document cites its record instead of "
    "removing it.",
    "Notes and conclusions are the investigator's statements, not Telegram observations.",
)
PALETTES = {
    "light": "--bg:#ffffff;--page:#f3f5f9;--fg:#111827;--muted:#5b6676;--ref:#8a95a5;--line:#e3e7ee;--rail:#d3dae4;"
             "--nav:#fbfcfe;--surface:#ffffff;--surface-2:#f5f7fa;--accent:#2563eb;--accent-soft:#eaf1fe;"
             "--accent-line:#c3d5fb;--ok:#15803d;--ok-soft:#e8f5ec;--ok-line:#b9e2c5;--warn:#c0322b;--warn-soft:#fdf0ee;"
             "--warn-line:#f2c2bb;--amber:#a15c07;--amber-soft:#fef5e2;--amber-line:#f3d9a3;--violet:#7c3aed;"
             "--violet-soft:#f3eefe;--violet-line:#dacbfb;--blue:#1d5fbf;--blue-soft:#eaf2fd;--blue-line:#c3d8f6;"
             "--bot:#0f766e;--bot-line:#a9dccf;--bubble-in:#f1f4f9;--bubble-bot:#ecf7f3;--bubble-out:#e3eefe;"
             "--lag:#94580a;--lag-soft:#fff3d9;--shadow:0 1px 2px rgba(16,24,40,.05),0 3px 10px rgba(16,24,40,.06)",
    "dark": "--bg:#0f1720;--page:#0b1118;--fg:#e6edf5;--muted:#9aa9ba;--ref:#7d8fa3;--line:#223142;--rail:#2b3d50;"
            "--nav:#0f1720;--surface:#121c27;--surface-2:#172331;--accent:#6aa5ff;--accent-soft:#132a47;"
            "--accent-line:#22446e;--ok:#4ade80;--ok-soft:#10301f;--ok-line:#1d5236;--warn:#ff8a7a;--warn-soft:#3a1714;"
            "--warn-line:#6b2a23;--amber:#f5c065;--amber-soft:#33260c;--amber-line:#5c461a;--violet:#c4a1ff;"
            "--violet-soft:#271b40;--violet-line:#45306e;--blue:#7fb3ff;--blue-soft:#14263f;--blue-line:#244368;"
            "--bot:#5eead4;--bot-line:#1f5b52;--bubble-in:#182432;--bubble-bot:#11302b;--bubble-out:#183a63;"
            "--lag:#f5c065;--lag-soft:#33260c;--shadow:0 1px 2px rgba(0,0,0,.35),0 4px 14px rgba(0,0,0,.25)"}
FONT = '"Inter","Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif'
MONO = 'ui-monospace,"Cascadia Mono","SFMono-Regular",Consolas,"Liberation Mono",monospace'
STYLE = (
    "*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--fg);font:15px/1.6 " + FONT + ";"
    "-webkit-font-smoothing:antialiased}.mono,code{font-family:" + MONO + ";font-size:.86em;overflow-wrap:anywhere}"
    "code{background:var(--surface-2);border:1px solid var(--line);border-radius:6px;padding:1px 5px}"
    ".shell{display:grid;grid-template-columns:268px minmax(0,1fr);min-height:100vh}"
    "nav{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;padding:28px 18px;background:var(--nav);"
    "border-right:1px solid var(--line)}.nav-title{font-weight:700;font-size:14px;line-height:1.35;margin:10px 10px 4px}"
    ".nav-sub{font-size:12px;color:var(--muted);margin:0 10px 18px}nav a{display:flex;gap:9px;align-items:center;"
    "color:var(--fg);text-decoration:none;font-size:13.5px;padding:7px 10px;border-radius:9px}"
    "nav a:hover{background:var(--surface-2)}nav a .icon{color:var(--muted)}nav a.sub{padding-left:26px;font-size:13px;"
    "color:var(--muted)}nav .brand{margin:0 10px}"
    "main{max-width:960px;width:100%;padding:40px 52px 64px}"
    ".icon{width:18px;height:18px;flex:none;vertical-align:-3px}.icon.s{width:14px;height:14px;vertical-align:-2px}"
    "h1{font-size:34px;line-height:1.15;letter-spacing:-.02em;margin:12px 0 8px}h2{font-size:21px;letter-spacing:-.01em;"
    "margin:0}.kicker{font-size:11.5px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--accent)}"
    ".brand{display:flex;gap:8px;align-items:center;font-size:12px;font-weight:700;letter-spacing:.12em;"
    "text-transform:uppercase;color:var(--accent)}"
    ".cover{position:relative;overflow:hidden;background:var(--surface);border:1px solid var(--line);border-radius:20px;"
    "padding:32px 34px 28px;box-shadow:var(--shadow)}.cover:before{content:\"\";position:absolute;inset:0 0 auto 0;"
    "height:6px;background:linear-gradient(90deg,var(--accent),var(--violet),var(--ok))}"
    ".purpose{font-size:16px;color:var(--muted);margin:0 0 6px;max-width:720px}"
    ".badges{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0 20px}.pill{display:inline-flex;gap:6px;align-items:center;"
    "border-radius:999px;padding:5px 12px;font-size:12.5px;font-weight:600;border:1px solid transparent}"
    ".pill.ok{background:var(--ok-soft);color:var(--ok);border-color:var(--ok-line)}"
    ".pill.draft{background:var(--amber-soft);color:var(--amber);border-color:var(--amber-line)}"
    ".pill.sig{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)}"
    ".pill.hide{background:var(--warn-soft);color:var(--warn);border-color:var(--warn-line)}"
    ".meta{display:grid;grid-template-columns:170px minmax(0,1fr);gap:9px 20px;margin:0;font-size:13.5px;"
    "padding-top:18px;border-top:1px solid var(--line)}.meta dt{color:var(--muted)}.meta dd{margin:0;overflow-wrap:anywhere}"
    ".cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:24px}"
    ".card{background:var(--surface-2);border:1px solid var(--line);border-radius:14px;padding:14px 14px 12px;display:flex;"
    "flex-direction:column;gap:4px}.card .icon{color:var(--accent);width:20px;height:20px}"
    ".card b{font-size:26px;line-height:1.1;letter-spacing:-.02em;font-variant-numeric:tabular-nums}"
    ".card span{font-size:12.5px;color:var(--muted)}.card.alert .icon,.card.alert b{color:var(--warn)}"
    ".block{margin-top:44px}.block>h2{display:flex;gap:10px;align-items:center;margin-bottom:12px}"
    ".block>h2 .icon{color:var(--accent);width:22px;height:22px}.lead{color:var(--muted);font-size:13.5px;margin:0 0 14px}"
    ".timeline{list-style:none;margin:30px 0 0;padding:0 0 0 32px;position:relative}"
    ".timeline:before{content:\"\";position:absolute;left:10px;top:6px;bottom:6px;width:2px;background:var(--rail);"
    "border-radius:2px}.item{position:relative;margin:0 0 20px}.item>.dot{position:absolute;left:-29px;top:5px;width:14px;"
    "height:14px;border-radius:50%;background:var(--surface);border:3px solid var(--rail)}"
    ".item.msg.in>.dot{border-color:var(--blue)}.item.msg.bot>.dot{border-color:var(--bot)}"
    ".item.msg.out>.dot{border-color:var(--accent)}.item.sys>.dot{width:10px;height:10px;left:-27px;top:8px;"
    "border-color:var(--muted)}.item.hidden>.dot,.item.alert>.dot{border-color:var(--warn)}"
    ".item.visual>.dot{border-color:var(--violet)}.item.note>.dot{border-color:var(--amber);border-radius:4px}"
    ".row-meta{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;font-size:12px;color:var(--muted);"
    "margin-bottom:7px}.row-meta .no{font-weight:700;color:var(--fg);letter-spacing:.02em}"
    "time{font-variant-numeric:tabular-nums}.item.msg.out .row-meta,.item.msg.out .ref{justify-content:flex-end}"
    ".chip{display:inline-flex;gap:5px;align-items:center;border-radius:999px;padding:2px 9px;font-size:11.5px;"
    "font-weight:600;background:var(--surface-2);border:1px solid var(--line);color:var(--muted)}"
    ".chip.lag{background:var(--lag-soft);color:var(--lag);border-color:transparent}"
    ".chip.video{background:var(--blue-soft);color:var(--blue);border-color:transparent;font-family:var(--mono)}"
    ".chip.ioc{background:var(--surface);color:var(--fg)}"
    ".bubble{position:relative;max-width:640px;border-radius:16px;padding:10px 14px 11px;background:var(--bubble-in);"
    "border:1px solid var(--line);box-shadow:var(--shadow)}.bubble.in{border-top-left-radius:5px}"
    ".bubble.bot{background:var(--bubble-bot);border-color:var(--bot-line)}"
    ".bubble.out{margin-left:auto;background:var(--bubble-out);border-color:var(--accent-line);"
    "border-top-right-radius:5px}.who{font-size:12.5px;font-weight:700;color:var(--blue);margin-bottom:3px}"
    ".bubble.bot .who{color:var(--bot)}.bubble.out .who{color:var(--accent)}"
    ".who .tags{font-weight:500;color:var(--muted);margin-left:6px}"
    ".text{white-space:pre-wrap;overflow-wrap:anywhere;font-size:14.5px}"
    ".translation{margin-top:8px;padding:7px 10px;border-left:3px solid var(--blue);border-radius:6px;"
    "background:var(--surface-2);white-space:pre-wrap;overflow-wrap:anywhere;font-size:13.5px}"
    ".translation b{display:block;margin-bottom:2px;font-size:11px;font-weight:700;letter-spacing:.02em;color:var(--muted)}"
    ".buttons{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}.buttons span{flex:1 1 auto;text-align:center;"
    "font-size:12.5px;font-weight:600;padding:6px 10px;border-radius:9px;background:var(--surface);"
    "border:1px solid var(--line);color:var(--accent)}"
    ".media{display:flex;gap:6px;align-items:center;font-size:12px;color:var(--muted);margin-top:6px}"
    ".sys-line{display:flex;gap:10px;align-items:flex-start;font-size:14px;background:var(--surface);"
    "border:1px solid var(--line);border-radius:12px;padding:9px 13px;box-shadow:var(--shadow)}"
    ".sys-line .icon{color:var(--muted);margin-top:2px}.item.alert .sys-line .icon{color:var(--warn)}"
    ".item.visual .sys-line .icon{color:var(--violet)}"
    ".item.minor .sys-line{background:transparent;border-style:dashed;box-shadow:none;font-size:12.5px;"
    "color:var(--muted);padding:6px 11px}"
    ".hidden-box{display:flex;gap:10px;align-items:center;background:var(--warn-soft);color:var(--warn);"
    "border:1px dashed var(--warn-line);border-radius:12px;padding:11px 14px;font-weight:600;font-size:13.5px}"
    ".callout{display:flex;gap:10px;align-items:flex-start;margin-top:9px;border-radius:12px;padding:10px 13px;"
    "max-width:640px;overflow-wrap:anywhere;font-size:13px;border:1px solid var(--warn-line);background:var(--warn-soft)}"
    ".item.msg.out .callout{margin-left:auto}.item.msg.out .extras{justify-content:flex-end}"
    ".callout .mono{display:block;margin-top:3px}.callout .icon{color:var(--warn);"
    "margin-top:1px}.callout b{display:block;color:var(--warn);font-size:11.5px;letter-spacing:.06em;"
    "text-transform:uppercase;margin-bottom:2px}.extras{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}"
    ".ref{display:flex;gap:6px;align-items:center;margin-top:8px;font-size:11.5px;color:var(--ref)}"
    "figure.shot{margin:10px 0 0;border:1px solid var(--line);border-radius:14px;overflow:hidden;"
    "background:var(--surface);box-shadow:var(--shadow);max-width:700px}.chrome{display:flex;gap:6px;align-items:center;"
    "padding:8px 12px;background:var(--surface-2);border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}"
    ".chrome i{width:10px;height:10px;border-radius:50%;background:var(--line);display:inline-block}"
    ".chrome span{margin-left:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
    "figure.shot img{display:block;width:100%;height:auto}figure.shot figcaption{padding:8px 12px;font-size:11.5px;"
    "color:var(--ref);border-top:1px solid var(--line)}"
    ".divider{list-style:none;margin:36px 0 22px -32px;position:relative}.divider .ep{display:flex;gap:14px;"
    "align-items:flex-start;padding:16px 18px;border-radius:16px;background:var(--surface);border:1px solid var(--line);"
    "box-shadow:var(--shadow)}.divider .ep>.icon{width:28px;height:28px;color:var(--accent);margin-top:3px}"
    ".divider p{margin:5px 0 0;font-size:13px;color:var(--muted)}.divider.cont{margin-top:22px}"
    ".divider.cont .ep{padding:8px 14px;box-shadow:none}.divider.cont h2{font-size:15px}"
    ".note-card{border-radius:14px;padding:12px 15px;background:var(--surface);border:1px solid var(--line);"
    "border-left:5px solid var(--muted);box-shadow:var(--shadow)}.note-card.important{border-left-color:var(--amber)}"
    ".note-card.conclusion{border-left-color:var(--blue)}.note-card.question{border-left-color:var(--violet)}"
    ".note-card.decision{border-left-color:var(--accent)}.label.decision{background:var(--surface-2);color:var(--accent)}"
    ".note-card.hide{border-left-color:var(--warn)}.note-text{white-space:pre-wrap;margin-top:6px;font-size:14.5px}"
    ".labels{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:12px;color:var(--muted)}"
    ".label{border-radius:999px;padding:2px 10px;font-size:11.5px;font-weight:700;background:var(--surface-2);color:var(--fg)}"
    ".label.conclusion{background:var(--blue-soft);color:var(--blue)}.label.important{background:var(--amber-soft);"
    "color:var(--amber)}.label.question{background:var(--violet-soft);color:var(--violet)}"
    ".label.hide{background:var(--warn-soft);color:var(--warn)}"
    ".concl{display:grid;gap:12px}.concl-card{display:grid;grid-template-columns:40px 1fr;gap:14px;align-items:start;"
    "background:var(--blue-soft);border:1px solid var(--blue-line);border-radius:16px;padding:16px 18px}"
    ".concl-card .num{width:40px;height:40px;border-radius:12px;background:var(--blue);color:var(--surface);display:grid;"
    "place-items:center;font-weight:800;font-size:17px}.concl-card p{margin:0;font-size:15.5px;font-weight:500;"
    "white-space:pre-wrap;overflow-wrap:anywhere}.concl-card small{display:block;margin-top:6px;color:var(--muted)}"
    "table{border-collapse:separate;border-spacing:0;width:100%;font-size:13px;border:1px solid var(--line);"
    "border-radius:12px;overflow:hidden;background:var(--surface)}th{background:var(--surface-2);text-align:left;"
    "font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}td,th{padding:9px 12px;"
    "border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}tr:last-child td{border-bottom:0}"
    ".kind{display:inline-block;border-radius:6px;padding:1px 8px;font-size:11.5px;font-weight:700;"
    "background:var(--surface-2);color:var(--fg)}.k-wallet{background:var(--amber-soft);color:var(--amber)}"
    ".k-url,.k-domain{background:var(--blue-soft);color:var(--blue)}.k-telegram,.k-telegram-invite{"
    "background:var(--accent-soft);color:var(--accent)}.k-email,.k-phone{background:var(--violet-soft);color:var(--violet)}"
    ".howto ul{margin:0;padding:0;list-style:none;display:grid;gap:8px}.howto li{display:flex;gap:10px;"
    "align-items:flex-start;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:10px 14px;"
    "font-size:13.5px}.howto li .icon{color:var(--accent);margin-top:2px}"
    ".doc-foot{margin-top:44px;padding-top:16px;border-top:1px solid var(--line);font-size:12px;color:var(--ref);"
    "display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}"
    "@media(max-width:900px){.shell{display:block}nav{position:static;height:auto}main{padding:24px 16px}"
    ".cards{grid-template-columns:repeat(2,minmax(0,1fr))}.meta{grid-template-columns:1fr}}")
SUBJECT_CSS = (
    ".subject{border:1px solid var(--line);border-radius:16px;background:var(--surface);box-shadow:var(--shadow);overflow:hidden}"
    ".subject-head{display:flex;gap:14px;align-items:center;padding:14px 16px;background:linear-gradient(120deg,var(--blue-soft),var(--surface) 80%)}"
    ".subject .avatar{flex:none;width:64px;height:64px;border-radius:50%;overflow:hidden;display:grid;place-items:center;"
    "background:var(--surface-2);border:2px solid var(--surface);box-shadow:var(--shadow);font-size:22px;font-weight:700;color:var(--blue)}"
    ".subject .avatar img{width:100%;height:100%;object-fit:cover}.subject-id b{font-size:17px}"
    ".subject-id .handles{color:var(--blue);font-weight:600;font-size:13.5px}.subject-id .mono{color:var(--muted);font-size:12px}"
    ".subject-flags{display:flex;flex-wrap:wrap;gap:5px;margin-top:5px}.subject .flag{font-size:10.5px;font-weight:800;letter-spacing:.06em;"
    "padding:2px 7px;border-radius:999px;background:var(--surface-2);color:var(--muted);border:1px solid var(--line)}"
    ".subject .flag.scam,.subject .flag.fake{background:var(--warn-soft,#fde8e8);color:var(--warn,#c0392b);border-color:transparent}"
    ".subject .flag.verified{background:var(--blue-soft);color:var(--blue);border-color:transparent}"
    ".subject-body{display:grid;gap:8px;padding:12px 16px 14px;font-size:13.5px}.subject-body .label-row{color:var(--muted);"
    "font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}.subject-body p{margin:0;white-space:pre-wrap;"
    "overflow-wrap:anywhere}.commands{display:flex;flex-wrap:wrap;gap:5px}.commands span{font-family:var(--mono);font-size:12px;"
    "padding:2px 8px;border-radius:7px;background:var(--surface-2);border:1px solid var(--line)}"
    ".subject-facts{display:flex;flex-wrap:wrap;gap:6px 14px;color:var(--muted);font-size:12.5px}"
    ".subject-changes{border-left:3px solid var(--amber,#d68910);padding:6px 10px;border-radius:6px;background:var(--surface-2)}"
    ".subject-foot{padding:8px 16px;border-top:1px solid var(--line);color:var(--muted);font-size:11.5px}"
)
STYLE += SUBJECT_CSS
PRINT = ("body{background:#fff;font-size:10.5pt}.shell{display:block}nav{display:none}main{max-width:none;padding:0}"
         ".cover{box-shadow:none;break-after:page}.card,.bubble,.sys-line,.callout,figure,.note-card,.concl-card,tr,"
         ".divider,.hidden-box,.howto li{break-inside:avoid}h2{break-after:avoid}.bubble,figure.shot,.divider .ep,"
         ".note-card,.sys-line{box-shadow:none}a{color:inherit;text-decoration:none}"
         "*{-webkit-print-color-adjust:exact;print-color-adjust:exact}")
ICONS = {
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    "message": '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    "timer": '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2M9 2h6"/>',
    "trash": '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>',
    "image": '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/>',
    "alert": '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
    "flag": '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1zM4 22v-7"/>',
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "link": '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
    "send": '<path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/>',
    "eye": '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>',
    "check": '<path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><path d="M22 4L12 14l-3-3"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
    "more": '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
    "help": '<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01"/>',
    "key": '<circle cx="7.5" cy="15.5" r="5.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
    "search": '<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/>',
    "book": '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V2H6.5A2.5 2.5 0 0 0 4 4.5zM4 19.5A2.5 2.5 0 0 0 6.5 22H20v-5"/>',
}
SYSTEM_ICONS = {"checked_link": "link", "requested": "send", "observing": "eye", "outcome": "check", "deleted": "trash",
                "not_listed": "more", "self_check": "shield", "visual": "globe", "account_change": "key", "search_recorded": "search", "subject": "eye", "peer_settings": "globe", "presence": "timer", "qr_code": "image", "watchlist_hit": "flag",
                "ai_draft": "flag"}
MESSAGE_TYPES = ("sent", "sent_elsewhere", "reply", "edited")
EPISODE_KINDS = {"bot": "Bot", "user": "Person", "private": "Person", "channel": "Channel", "group": "Group",
                 "supergroup": "Group", "megagroup": "Group"}
NOTE_KINDS = ("conclusion", "decision", "important", "question")
CSP = ("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; "
       "img-src data:; base-uri 'none'; form-action 'none'\">")


def e(value):
    return html.escape(str(value), quote=True)


def icon(name, cls="icon"):
    return ('<svg class="' + cls + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + ICONS[name] + "</svg>")


def css_string(value):
    return '"' + "".join("\\%x " % ord(c) if c in '\\"<>' or ord(c) < 32 else c for c in str(value)) + '"'


def page_start(say, title, theme, style):
    return ('<!doctype html><html lang="' + e(getattr(say, "language", "en")) + '"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">' + CSP
            + '<meta name="generator" content="TgWitness"><title>' + e(title) + "</title><style>:root{color-scheme:"
            + theme + ";" + PALETTES[theme] + "}" + style + "</style>")


def status_text(fixed, say):
    return (say("Fixed document. Statement SHA-256: {digest}", digest=fixed["statement_sha256"]) if fixed
            else say("Draft. Not signed; it can still change."))


def summary_cards(known, say):
    fastest = say("{n} s", n=action_protocol.pretty(known["fastest"])) if known["fastest"] is not None else "—"
    return [("list", known["steps"], say("steps"), False), ("message", known["replies"], say("replies or edits"), False),
            ("timer", fastest, say("fastest reply"), False), ("trash", known["deletions"], say("deletion notices"), False),
            ("image", known["files"], say("files and screenshots"), False),
            ("alert", known["risky"], say("risky or deceptive links"), bool(known["risky"])),
            ("flag", known["conclusions"], say("conclusions"), False),
            ("lock", known["hidden"], say("hidden for a stated reason"), False)]


def cards_html(cards):
    return '<div class="cards">' + "".join(
        '<div class="card' + (" alert" if alert else "") + '">' + icon(name) + "<b>" + e(value) + "</b><span>" + e(label)
        + "</span></div>" for name, value, label, alert in cards) + "</div>"


def episode_kind(episode, say):
    if episode.get("chat_id") is None:
        return say("Account and browser")
    return say(EPISODE_KINDS.get(episode.get("kind"), "Chat"))


def note_kind(mark):
    found = next((label for label in NOTE_KINDS if label in mark["labels"]), "")
    return found or ("hide" if any(label in HIDING for label in mark["labels"]) else "")


def labels_html(labels, say):
    shown = [label for label in labels if label in LABEL_NAMES]
    if not shown:
        return '<span class="label">' + e(say("Note")) + "</span>"
    return "".join('<span class="label ' + (label if label in NOTE_KINDS else "hide") + '">' + e(say(LABEL_NAMES[label]))
                   + "</span>" for label in shown)


def note_card(mark, say, clock):
    video = video_text(mark, say)
    return ('<div class="note-card ' + note_kind(mark) + '"><div class="labels">' + labels_html(mark["labels"], say)
            + "<time>" + e(clock(mark["at"])) + "</time></div><div class=\"note-text\">" + e(mark["text"]) + "</div>"
            + ('<div class="ref">' + icon("timer", "icon s") + e(video) + "</div>" if video else "") + "</div>")


def shots(step, images, say, address=None):
    found = ""
    for item in step.get("files") or []:
        source = (images or {}).get(item["sha256"])
        if source:
            found += ('<figure class="shot">' + ('<div class="chrome"><i></i><i></i><i></i><span>' + e(address)
                                                 + "</span></div>" if address else "")
                      + '<img alt="' + e(say("Screenshot {sha}", sha=item["sha256"][:16])) + '" src="' + e(source) + '">'
                      + '<figcaption>SHA-256 <span class="mono">' + e(item["sha256"]) + "</span></figcaption></figure>")
    return found


def callouts(step, say):
    found = ""
    if step.get("ai_draft"):
        found += ('<div class="callout">' + icon("flag") + "<div><b>" + e(say("AI-assisted message")) + "</b>"
                  + e(action_protocol.drafted_note(step["ai_draft"], say)) + "</div></div>")
    for item in step.get("deceptive_links") or []:
        found += ('<div class="callout">' + icon("alert") + "<div><b>" + e(say("Deceptive link")) + "</b>"
                  + e(say("The link text {text} opens {href}", text=action_protocol.quoted(item.get("text") or ""),
                          href=item.get("href") or "")) + "</div></div>")
    for item in step.get("risky_links") or []:
        found += ('<div class="callout">' + icon("alert") + "<div><b>" + e(say("Risky link")) + "</b>"
                  + e(say(action_protocol.RISKS.get(item.get("risk"), "Risky link."))) + '<span class="mono">'
                  + e(item.get("href") or item.get("text") or "") + "</span></div></div>")
    return found


def media_line(media, say):
    return " · ".join(str(part) for part in (media.get("kind"), media.get("file_name"), media.get("mime_type"),
                                             say("{n} bytes", n=media["size"]) if media.get("size") else None) if part)


def subject_card(step, say, images, clock):
    names = " · ".join("@" + name for name in step.get("usernames") or [])
    ident = step.get("user_id") or step.get("chat_id")
    photo = next(((images or {}).get(item["sha256"]) for item in step.get("files") or [] if item.get("role") == "avatar"), None)
    initials = "".join(part[:1] for part in (step.get("title") or "?").split()[:2]).upper() or "?"
    avatar = '<img alt="' + e(say("Profile photo")) + '" src="' + e(photo) + '">' if photo else e(initials)
    kind = say(action_protocol.SUBJECT_KINDS.get(step.get("kind"), "chat")).upper()
    badges = '<span class="flag">' + e(kind) + "</span>" + "".join(
        '<span class="flag ' + e(flag) + '">' + e(say(flag).upper()) + "</span>" for flag in step.get("flags") or []
        if flag != "bot")
    body = ""
    if step.get("about"):
        body += '<div><div class="label-row">' + e(say("Bio or description")) + "</div><p>" + e(step["about"]) + "</p></div>"
    if step.get("bot_description"):
        body += ('<div><div class="label-row">' + e(say("Bot description")) + "</div><p>" + e(step["bot_description"])
                 + "</p></div>")
    if step.get("commands"):
        body += ('<div><div class="label-row">' + e(say("Bot commands")) + '</div><div class="commands">'
                 + "".join("<span title=\"" + e(c.get("description") or "") + "\">/" + e(c.get("command") or "") + "</span>"
                           for c in step["commands"]) + "</div></div>")
    facts = [say("{n} members", n=step["participants"]) if step.get("participants") else "",
             say("created {at}", at=clock(step["created_at"])) if step.get("created_at") else "",
             say("{n} chats in common with this account", n=step["common_chats"]) if step.get("common_chats") else ""]
    if any(facts):
        body += '<div class="subject-facts">' + "".join("<span>" + e(f) + "</span>" for f in facts if f) + "</div>"
    if step.get("changes"):
        body += ('<div class="subject-changes"><div class="label-row">' + e(say("Changed since the previous snapshot"))
                 + "</div>" + "".join("<p>" + e(say(action_protocol.SUBJECT_FIELDS.get(c.get("field"), c.get("field", ""))))
                                      + ": " + e(action_protocol.shown_value(c.get("before"), say)) + " → "
                                      + e(action_protocol.shown_value(c.get("after"), say)) + "</p>"
                                      for c in step["changes"]) + "</div>")
    return ('<div class="subject"><div class="subject-head"><div class="avatar">' + avatar + '</div><div class="subject-id"><b>'
            + e(step.get("title") or say("Unnamed")) + "</b>" + ('<div class="handles">' + e(names) + "</div>" if names else "")
            + ('<div class="mono">' + e(say("Telegram ID {id}", id=ident)) + "</div>" if ident is not None else "")
            + '<div class="subject-flags">' + badges + "</div></div></div>" + ('<div class="subject-body">' + body + "</div>" if body else "")
            + '<div class="subject-foot">' + e(say("Snapshot taken {at}. What Telegram returned to this account at that moment.",
                                                   at=clock(step.get("at")))) + "</div></div>")


def translation_label(item, say):
    return say("Machine translation {source} → {target}, {model}, record #{seq}",
               source=(item.get("source_language") or "?").upper(), target=(item.get("target") or "?").upper(),
               model=item.get("model") or "?", seq=item.get("record", "?"))


def bubble(step, side, say, images, pictures=True):
    sender, kind = step.get("sender") or {}, step["type"]
    name = say("This account") if side == "out" else action_protocol.who(step, say)
    tags = ["#" + str(step["message_id"])] if step.get("message_id") is not None else []
    if side != "out" and sender.get("username") and "@" + sender["username"] != name:
        tags.append("@" + sender["username"])
    if side != "out" and sender.get("id") and (sender.get("display_name") or sender.get("username")):
        tags.append(say("ID {id}", id=sender["id"]))
    if step.get("reply_to_message_id"):
        tags.append(say("reply to #{id}", id=step["reply_to_message_id"]))
    if kind == "edited":
        tags.append(say("edited"))
    if kind == "sent_elsewhere":
        tags.append(say("from another app or session"))
    if step.get("ai_draft"):
        tags.append(say("AI-assisted"))
    media = step.get("media") or {}
    body = ('<div class="text">' + e(step["text"]) + "</div>" if step.get("text")
            else "" if media or step.get("files") else '<div class="text">' + e(say("Message without text.")) + "</div>")
    if step.get("translation"):
        body += ('<div class="translation"><b>' + e(translation_label(step["translation"], say)) + "</b>"
                 + e(step["translation"]["text"]) + "</div>")
    if media:
        body += '<div class="media">' + icon("image", "icon s") + e(media_line(media, say)) + "</div>"
    for row in step.get("buttons") or []:
        body += '<div class="buttons">' + "".join("<span>" + e(label) + "</span>" for label in row if label) + "</div>"
    if pictures:
        body += shots(step, images, say)
    elif step.get("files"):
        body += ('<div class="media">' + icon("image", "icon s") + e(say("{n} files saved.", n=len(step["files"])))
                 + "</div>")
    return ('<div class="bubble ' + side + '"><div class="who">' + e(name)
            + ('<span class="tags">' + e(" · ".join(tags)) + "</span>" if tags else "") + "</div>" + body + "</div>")


def step_item(step, episode, number, say, clock, appearance, images, reference="", slim=False):
    kind, hidden = step["type"], step.get("hidden")
    message = kind in MESSAGE_TYPES and not hidden
    side = ("out" if kind in ("sent", "sent_elsewhere") else "bot" if episode.get("kind") == "bot" else "in") \
        if message else ""
    alert = not hidden and (step.get("deceptive_links") or step.get("risky_links") or step.get("risks")
                            or (kind == "outcome" and step.get("status") in ("rejected", "unknown")))
    lag = action_protocol.delay(step, say)
    meta = ('<div class="row-meta"><span class="no">' + e(say("Step {n}", n=number)) + "</span><time>"
            + e(clock(step.get("at"))) + "</time>"
            + ('<span class="chip lag">' + icon("timer", "icon s") + e(lag) + "</span>" if lag else "")
            + ('<span class="chip">' + e(say("Telegram time {at}", at=clock(step["telegram_time"]))) + "</span>"
               if message and step.get("telegram_time") else "")
            + ('<span class="chip video">' + icon("timer", "icon s") + e(say("Video {at}", at=video_clock(step["video"])))
               + "</span>" if step.get("video") else "") + "</div>")
    if hidden:
        content = '<div class="hidden-box">' + icon("lock") + "<span>" + e(step_line(step, say, clock)) + "</span></div>"
    elif kind == "subject":
        content = subject_card(step, say, images, clock)
    elif message:
        content = bubble(step, side, say, images, not slim)
    else:
        name = "alert" if alert else SYSTEM_ICONS.get(kind, "more")
        content = ('<div class="sys-line">' + icon(name) + "<div>" + e(step_line(step, say, clock)) + "</div></div>"
                   + ("" if slim else shots(step, images, say, step.get("final_url") or step.get("url"))))
    if not hidden:
        content += callouts(step, say)
    if appearance.detail == "full" and not slim and not hidden:
        chips = ["<span class=\"chip\">" + icon("image", "icon s") + e(say("Saved file")) + ' <span class="mono">'
                 + e(shown_hash(item["sha256"], appearance)) + "</span></span>" for item in step.get("files") or []]
        chips += ['<span class="chip ioc"><span class="kind k-' + e(item["kind"]) + '">' + e(say(item["kind"]))
                  + "</span><span class=\"mono\">" + e(item["value"]) + "</span></span>"
                  for item in step.get("indicators") or []]
        content += '<div class="extras">' + "".join(chips) + "</div>" if chips else ""
    classes = ("item " + ("msg " + side if message else "sys") + (" minor" if action_protocol.minor(step) else "")
               + (" hidden" if hidden else "") + (" alert" if alert else "") + (" visual" if kind == "visual" else "")
               + (" long" if message and len(step.get("text") or "") > 500 else ""))
    return ('<li class="' + classes + '" id="s' + str(number) + '"><span class="dot"></span>' + meta + content
            + ('<div class="ref">' + icon("shield", "icon s") + reference + "</div>" if reference and not slim else "")
            + "</li>")


class Appearance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    offset_minutes: int = Field(default=0, ge=-720, le=840)
    hashes: Literal["short", "full", "appendix"] = "short"
    images: Literal["inline", "none"] = "inline"
    theme: Literal["light", "dark"] = "light"
    detail: Literal["full", "compact"] = "full"
    summary: bool = True
    found: bool = True
    preset: Literal["custom", "court", "briefing", "internal"] = "custom"
    subjects: bool = True
    notes: bool = True
    conclusions: bool = True
    translations: bool = True
    references: bool = True
    limits: bool = True

    @model_validator(mode="after")
    def court_keeps_limits(self):
        if self.preset == "court":
            self.limits = self.references = True
        return self


PRESETS = {
    "court": {"hashes": "full", "images": "inline", "theme": "light", "detail": "full", "summary": True, "found": True,
              "subjects": True, "notes": True, "conclusions": True, "translations": True, "references": True, "limits": True},
    "briefing": {"hashes": "short", "images": "inline", "theme": "light", "detail": "compact", "summary": True,
                 "found": True, "subjects": True, "notes": False, "conclusions": True, "translations": True,
                 "references": False, "limits": True},
    "internal": {"hashes": "short", "images": "inline", "theme": "dark", "detail": "full", "summary": True, "found": True,
                 "subjects": True, "notes": True, "conclusions": True, "translations": True, "references": True,
                 "limits": False},
}


def shaped(model, appearance):
    blocks = []
    for block in model["blocks"]:
        if block["type"] == "mark":
            if appearance.notes:
                blocks.append(block)
            continue
        step = block["step"]
        if step["type"] == "subject" and not appearance.subjects:
            continue
        if step.get("translation") and not appearance.translations:
            step = {key: value for key, value in step.items() if key != "translation"}
            block = {**block, "step": step}
        blocks.append(block)
    return {**model, "blocks": blocks, "conclusions": model["conclusions"] if appearance.conclusions else [],
            "limits": model["limits"] if appearance.limits else []}


def appearance_of(session):
    try:
        return Appearance(**(session.get("appearance") or {}))
    except ValueError:
        return Appearance()


def shown_time(value, appearance):
    parsed = action_protocol.moment(value)
    if parsed is None:
        return value or ""
    local = parsed.astimezone(timezone.utc) + timedelta(minutes=appearance.offset_minutes)
    return local.strftime("%Y-%m-%d %H:%M:%S") + " " + zone_name(appearance.offset_minutes)


def zone_name(offset):
    return "UTC" if not offset else "UTC%s%02d:%02d" % ("+" if offset > 0 else "−", abs(offset) // 60, abs(offset) % 60)


def indicator_items(model):
    from .indicators import Indicators
    found = Indicators()
    for block in model["blocks"]:
        step = block.get("step") or {}
        if block["type"] != "step" or step.get("hidden"):
            continue
        ref = {key: value for key, value in (("chat", block.get("chat_id")), ("message", step.get("message_id")),
                                              ("seq", (step.get("ref") or {}).get("seq"))) if value is not None}
        for item in step.get("indicators") or []:
            found.note(item["kind"], item["value"], "message", ref, step.get("at"),
                       **{key: item[key] for key in ("chain", "punycode") if key in item})
    return found.result()["items"]


def facts(model):
    steps = [b["step"] for b in model["blocks"] if b["type"] == "step"]
    marks = [b["mark"] for b in model["blocks"] if b["type"] == "mark"]
    summaries = [episode.get("summary") or {} for episode in model["episodes"]]
    fastest = [s["first_reply_seconds"] for s in summaries if isinstance(s.get("first_reply_seconds"), (int, float))]
    times = [s.get("at") for s in steps if s.get("at")]
    return {"steps": len(steps), "replies": sum(s.get("replies", 0) for s in summaries),
            "fastest": min(fastest) if fastest else None, "deletions": sum(s.get("deletions", 0) for s in summaries),
            "files": sum(len(s.get("files") or []) for s in steps if not s.get("hidden")),
            "risky": sum(s.get("risky_links", 0) + s.get("deceptive_links", 0) for s in summaries),
            "notes": len(marks), "conclusions": len(model["conclusions"]),
            "hidden": sum(bool(s.get("hidden")) for s in steps),
            "from": min(times) if times else None, "to": max(times) if times else None}


def signer(fixed):
    key = ((fixed or {}).get("signed") or {}).get("statement", {}).get("public_key")
    return hashlib.sha256(base64.b64decode(key)).hexdigest() if key else None


def shown_hash(value, appearance):
    value = str(value or "")
    return value if appearance.hashes == "full" else value[:16] + "…" if value else ""


class Start(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=1, max_length=200)
    purpose: str = Field(default="", max_length=2000)
    chat_ids: list[int] = Field(default_factory=list, max_length=200)


class Mark(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    text: str = Field(min_length=1, max_length=5000)
    labels: list[Literal[LABELS]] = Field(default_factory=list, max_length=len(LABELS))
    target_seq: int | None = Field(default=None, ge=1)


def latest_seq(store):
    found = store.events(limit=1)
    return found[0]["seq"] if found else 0


def load(store, session_id):
    session = store.get_setting(PREFIX + session_id, None) if isinstance(session_id, str) and \
        len(session_id) == 32 and all(c in "0123456789abcdef" for c in session_id) else None
    if session is None:
        raise KeyError(session_id)
    return session


def save(store, session):
    store.set_setting(PREFIX + session["id"], session)
    return session


def draft(session):
    if session["fixed"]:
        raise ValueError("This document is fixed. Start a new revision to change it.")
    return session


def listing(store, chats=None):
    result = []
    for session_id in store.get_setting(INDEX, None) or []:
        session = store.get_setting(PREFIX + session_id, None)
        if session and (chats is None or session["chat_ids"] and set(session["chat_ids"]) <= chats):
            result.append({key: session[key] for key in ("id", "title", "state", "created_at", "chat_ids")}
                          | {"marks": len(session["marks"]), "fixed": bool(session["fixed"])})
    return result


RECORDING_FIELDS = ("recorder", "observer_id", "recording_started_at", "video_started_event")


def bind_recording(session, video):
    if not video or not video.get("recording_started_at"):
        return False
    recordings = session.setdefault("recordings", [])
    if any(item.get("video_started_event") == video.get("video_started_event") for item in recordings):
        return False
    recordings.append({key: video.get(key) for key in RECORDING_FIELDS})
    recordings.sort(key=lambda item: item["recording_started_at"])
    return True


def create(store, body, owner, chats=None, previous=None, video=None):
    if chats is not None and (not body.chat_ids or not set(body.chat_ids) <= chats):
        raise ValueError("Choose chats that this access can open.")
    session = {"id": secrets.token_hex(16), "title": body.title, "purpose": body.purpose,
               "chat_ids": sorted(set(body.chat_ids)), "owner": owner, "created_at": utcnow(), "state": "recording",
               "from_seq": latest_seq(store) + 1, "to_seq": None, "pauses": [], "marks": [], "fixed": None,
               "revision": 1, "previous": previous}
    bind_recording(session, video)
    with store.transaction():
        index = store.get_setting(INDEX, None) or []
        if len(index) >= MAX_SESSIONS:
            raise ValueError("Delete an old documentation draft first.")
        store.set_setting(INDEX, index + [session["id"]])
        save(store, session)
    return session


def control(store, session_id, action):
    with store.transaction():
        session = draft(load(store, session_id))
        now = latest_seq(store)
        if action == "pause" and session["state"] == "recording":
            session["state"] = "paused"
            session["pauses"].append({"from_seq": now + 1, "to_seq": None, "at": utcnow()})
        elif action == "resume" and session["state"] == "paused":
            session["state"] = "recording"
            session["pauses"][-1]["to_seq"] = now
        elif action == "stop" and session["state"] != "stopped":
            if session["state"] == "paused":
                session["pauses"][-1]["to_seq"] = now
            session.update(state="stopped", to_seq=now)
        elif action == "restart":
            session.update(state="recording", from_seq=now + 1, to_seq=None, pauses=[], marks=[],
                           revision=session["revision"] + 1)
        else:
            raise ValueError("This action does not apply to the document's current state.")
        return save(store, session)


def delete(store, session_id):
    with store.transaction():
        load(store, session_id)
        store.set_setting(PREFIX + session_id, None)
        store.set_setting(INDEX, [i for i in store.get_setting(INDEX, None) or [] if i != session_id])


def clock(seconds):
    seconds = int(seconds)
    return "%02d:%02d:%02d" % (seconds // 3600, seconds // 60 % 60, seconds % 60)


def undercover_snapshot(store, chats):
    if chats is not None:
        return None
    from .undercover import snapshot
    return snapshot(store)


def in_recording(at, recordings):
    chosen = None
    for index, item in enumerate(recordings):
        offset = action_protocol.seconds(at, item.get("recording_started_at"))
        if offset is not None and offset >= 0:
            chosen = {"recording": index + 1, "offset_seconds": round(offset, 1)}
    return chosen


def cue_time(seconds, separator):
    millis = int(round(max(seconds, 0) * 1000))
    return "%02d:%02d:%02d%s%03d" % (millis // 3600000, millis // 60000 % 60, millis // 1000 % 60, separator, millis % 1000)


def subtitles(model, say=action_protocol.plain_say, appearance=None, fmt="vtt", recording=1):
    appearance = appearance or Appearance()
    model = shaped(model, appearance)
    clock_text = lambda value: shown_time(value, appearance)  # noqa: E731
    cues, number = [], 0
    recordings = model.get("recordings") or []
    started = recordings[recording - 1].get("video_started_event") if 0 < recording <= len(recordings) else None
    for block in model["blocks"]:
        if block["type"] == "step":
            number += 1
            video = block["step"].get("video") or {}
            if video.get("recording") == recording:
                line = step_line(block["step"], say, clock_text).replace("\n", " ")
                cues.append((video["offset_seconds"], say("Step {n}", n=number) + " · " + clock_text(block["step"].get("at"))
                             + "\n" + (line if len(line) <= 160 else line[:159] + "…")))
        else:
            mark = block["mark"]
            video = mark.get("video") or {}
            if video.get("offset_seconds") is not None and started and video.get("video_started_event") == started:
                text = mark["text"].replace("\n", " ")
                cues.append((video["offset_seconds"], say("Note") + " · " + (text if len(text) <= 160 else text[:159] + "…")))
    cues.sort(key=lambda cue: cue[0])
    separator = "." if fmt == "vtt" else ","
    lines = ["WEBVTT", ""] if fmt == "vtt" else []
    for index, (start, text) in enumerate(cues):
        end = min(start + 6, cues[index + 1][0]) if index + 1 < len(cues) else start + 6
        end = max(end, start + 1.5)
        if fmt == "srt":
            lines.append(str(index + 1))
        lines += [cue_time(start, separator) + " --> " + cue_time(end, separator), text, ""]
    return "\n".join(lines)


def add_mark(store, session_id, body, video=None):
    with store.transaction():
        session = draft(load(store, session_id))
        if len(session["marks"]) >= MAX_MARKS:
            raise ValueError("This document has the maximum number of notes.")
        mark = {"id": secrets.token_hex(8), "at": utcnow(), "anchor_seq": latest_seq(store), "text": body.text,
                "labels": list(dict.fromkeys(body.labels)), "target_seq": body.target_seq}
        bind_recording(session, video)
        offset = action_protocol.seconds(mark["at"], (video or {}).get("recording_started_at"))
        if offset is not None and offset >= 0:
            mark["video"] = {**video, "offset_seconds": round(offset, 1)}
        session["marks"].append(mark)
        save(store, session)
    return mark


def edit_mark(store, session_id, mark_id, body):
    with store.transaction():
        session = draft(load(store, session_id))
        mark = next((m for m in session["marks"] if m["id"] == mark_id), None)
        if mark is None:
            raise KeyError(mark_id)
        mark.update(text=body.text, labels=list(dict.fromkeys(body.labels)), target_seq=body.target_seq,
                    edited_at=utcnow())
        save(store, session)
    return mark


def set_appearance(store, session_id, body):
    with store.transaction():
        session = load(store, session_id)
        session["appearance"] = body.model_dump()
        save(store, session)
    return session["appearance"]


def remove_mark(store, session_id, mark_id):
    with store.transaction():
        session = draft(load(store, session_id))
        kept = [m for m in session["marks"] if m["id"] != mark_id]
        if len(kept) == len(session["marks"]):
            raise KeyError(mark_id)
        session["marks"] = kept
        save(store, session)


def inside(session, seq, last):
    return session["from_seq"] <= seq <= last and not any(
        p["from_seq"] <= seq <= (p["to_seq"] if p["to_seq"] is not None else last) for p in session["pauses"])


def hidden_targets(marks):
    found = {}
    for mark in marks:
        labels = [label for label in mark["labels"] if label in HIDING]
        if mark.get("target_seq") and labels:
            found.setdefault(mark["target_seq"], set()).update(labels)
    return found


def encoded(data):
    return base64.b64encode(data).decode("ascii")


def reason_key(master, label):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=SEAL_INFO + label.encode("ascii")).derive(master)


def seal(store, model, master):
    sealed = []
    for block in model["blocks"]:
        step = block.get("step") or {}
        ref = step.get("ref") or {}
        if block["type"] != "step" or not step.get("hidden_labels") or not ref.get("seq"):
            continue
        found = store.events(after=ref["seq"] - 1, limit=1)
        if not found or found[0]["seq"] != ref["seq"] or found[0]["hash"] != ref["hash"]:
            raise ValueError("A hidden journal record could not be read for sealing. Refresh and fix again.")
        plain = canonical({key: found[0][key] for key in EVENT_FIELDS})
        if hashlib.sha256(plain).hexdigest() != ref["hash"]:
            raise ValueError("A hidden journal record does not match its hash. Verify the journal first.")
        content, nonce, aad = os.urandom(32), os.urandom(12), bytes.fromhex(ref["hash"])
        entry = {"seq": ref["seq"], "hash": ref["hash"], "labels": step["hidden_labels"], "algorithm": "AES-256-GCM",
                 "key_derivation": "HKDF-SHA256", "nonce": encoded(nonce),
                 "ciphertext": encoded(AESGCM(content).encrypt(nonce, plain, aad)), "keys": {}}
        for label in step["hidden_labels"]:
            wrap = os.urandom(12)
            entry["keys"][label] = {"nonce": encoded(wrap),
                                    "wrapped": encoded(AESGCM(reason_key(master, label)).encrypt(wrap, content, aad))}
        sealed.append(entry)
    return sealed


def document(store, session, chats=None):
    require_scope(session, chats)
    last = session["to_seq"] if session["to_seq"] is not None else latest_seq(store)
    wanted = set(session["chat_ids"]) or None
    scope = wanted if wanted is not None else chats
    protocol = action_protocol.collect(store, chats=scope, include=wanted,
                                       since_seq=session["from_seq"], account=scope is None)
    hidden = hidden_targets(session["marks"])
    blocks, episodes, translated = [], [], {}
    for episode in protocol["episodes"]:
        kept, keep_next = [], False
        for step in episode["steps"]:
            seq = (step.get("ref") or {}).get("seq")
            keep = inside(session, seq, last) if seq else keep_next
            keep_next = keep
            if not keep:
                continue
            step = dict(step)
            if seq in hidden:
                step = {key: step[key] for key in ("type", "at", "ref") if key in step}
                step["hidden_labels"] = sorted(hidden[seq])
                step["hidden"] = sorted({HIDING[label] for label in hidden[seq]})
            elif seq and step["type"] in MESSAGE_TYPES and episode["chat_id"] is not None:
                if episode["chat_id"] not in translated:
                    from .translation import latest
                    translated[episode["chat_id"]] = latest(store, episode["chat_id"])
                found = translated[episode["chat_id"]].get(seq)
                if found and (found.get("record") or 0) <= last:
                    step["translation"] = {key: found.get(key) for key in (
                        "text", "target", "source_language", "record", "model", "note", "source_sha256")}
            kept.append(step)
            blocks.append({"type": "step", "order": seq or 0, "chat_id": episode["chat_id"], "step": step})
        if kept:
            label = episode
            if any(step["type"] == "subject" and step.get("hidden") for step in kept):
                label = next((step for step in kept if step["type"] == "subject" and not step.get("hidden")), {})
            episodes.append({"chat_id": episode["chat_id"], "title": label.get("title"), "kind": label.get("kind"),
                             "steps": len(kept), "summary": action_protocol.summary({"steps": kept})})
    for mark in session["marks"]:
        blocks.append({"type": "mark", "order": mark["anchor_seq"] + 0.5, "mark": mark})
    blocks.sort(key=lambda block: block["order"])
    recordings = session.get("recordings") or []
    for block in blocks:
        if block["type"] == "step" and recordings:
            found = in_recording(block["step"].get("at"), recordings)
            if found:
                block["step"]["video"] = found
    return {"format": FORMAT, "session": {key: session[key] for key in (
                "id", "title", "purpose", "chat_ids", "created_at", "state", "from_seq", "to_seq", "pauses",
                "revision", "previous")},
            "last_seq": last, "episodes": episodes, "blocks": blocks, "recordings": recordings,
            **({"undercover": cover} if (cover := undercover_snapshot(store, scope)) else {}),
            "conclusions": [m for m in session["marks"] if "conclusion" in m["labels"]],
            "questions": [m for m in session["marks"] if "question" in m["labels"]],
            "truncated": protocol.get("truncated", False), "limits": list(LIMITS) + list(protocol["limits"])}


def manifest(model):
    items = []
    for block in model["blocks"]:
        if block["type"] == "step" and block["step"].get("ref"):
            ref = block["step"]["ref"]
            items.append({"type": "step", "seq": ref["seq"], "hash": ref["hash"],
                          **({"hidden": block["step"]["hidden"]} if block["step"].get("hidden") else {})})
        elif block["type"] == "mark":
            items.append({"type": "conclusion" if "conclusion" in block["mark"]["labels"] else "note",
                          "id": block["mark"]["id"], "sha256": hashlib.sha256(canonical(block["mark"])).hexdigest()})
    return items


def fix(store, vault, session_id, chats=None):
    with store.lock:
        require_scope(load(store, session_id), chats)
        return _fix_locked(store, vault, session_id, chats)


def _fix_locked(store, vault, session_id, chats=None):
    session = draft(load(store, session_id))
    if session["state"] != "stopped":
        session = control(store, session_id, "stop")
    model = document(store, session, chats)
    head = store.events(limit=1)
    master = os.urandom(32)
    sealed = seal(store, model, master)
    statement = {"format": FORMAT, "session_id": session["id"], "title": session["title"],
                 "purpose": session["purpose"], "revision": session["revision"], "previous": session["previous"],
                 "fixed_at": utcnow(), "public_key": vault.public_key,
                 "journal_head": {"seq": head[0]["seq"], "hash": head[0]["hash"]} if head else None,
                 "items": manifest(model), "marks": session["marks"], "sealed": sealed,
                 "document_sha256": hashlib.sha256(canonical(model)).hexdigest()}
    signed = {"statement": statement, "signature": vault.sign(canonical(statement))}
    digest = hashlib.sha256(canonical(statement)).hexdigest()
    if sealed:
        labels = sorted({label for entry in sealed for label in entry["labels"]})
        vault.save(KEYS_NAME + session_id, {"format": KEYS_FORMAT, "session_id": session_id, "statement_sha256": digest,
                                            "master": encoded(master),
                                            "labels": {label: encoded(reason_key(master, label)) for label in labels}})
    with store.transaction():
        current = draft(load(store, session_id))
        event = store.append("documentation.fixed", {
            "session_id": session_id, "title": session["title"], "statement_sha256": digest,
            "steps": sum(i["type"] == "step" for i in statement["items"]),
            "notes": sum(i["type"] == "note" for i in statement["items"]),
            "conclusions": sum(i["type"] == "conclusion" for i in statement["items"]), "sealed": len(sealed),
            "meaning": "The investigator fixed this documentation; later copies can be compared with this digest"})
        current["fixed"] = {"at": statement["fixed_at"], "event_seq": event["seq"], "statement_sha256": digest,
                            "sealed": len(sealed), "signed": signed, "model": model}
        save(store, current)
    return current


def revise(store, session_id, owner, chats=None):
    session = load(store, session_id)
    if not session["fixed"]:
        raise ValueError("Fix the document before starting a new revision.")
    revision = create(store, Start(title=session["title"], purpose=session["purpose"], chat_ids=session["chat_ids"]),
                      owner, chats, previous={"session_id": session_id,
                                              "statement_sha256": session["fixed"]["statement_sha256"]})
    with store.transaction():
        revision = load(store, revision["id"])
        revision.update(from_seq=session["from_seq"], pauses=list(session["pauses"]),
                        marks=[dict(m) for m in session["marks"]], revision=session["revision"] + 1,
                        recordings=[dict(r) for r in session.get("recordings") or []])
        return save(store, revision)


def require_scope(session, chats):
    if chats is None:
        return
    if not session["chat_ids"] or not set(session["chat_ids"]) <= chats:
        raise ValueError("This documentation is not open to this access.")
    fixed = session.get("fixed")
    if not fixed:
        return
    model = fixed["model"]
    scope = set(model["session"].get("chat_ids") or [])
    if not scope or not scope <= chats or model.get("undercover"):
        raise ValueError("This fixed documentation includes information outside this access.")
    for episode in model["episodes"]:
        if episode["chat_id"] is not None and episode["chat_id"] not in scope:
            raise ValueError("This fixed documentation includes information outside this access.")
    for block in model["blocks"]:
        if block["type"] != "step":
            continue
        chat_id, step = block.get("chat_id"), block["step"]
        if chat_id is None:
            search_scope = step.get("chats")
            if step["type"] == "search_recorded" and search_scope and set(search_scope) <= scope:
                continue
        elif chat_id in scope:
            continue
        raise ValueError("This fixed documentation includes information outside this access.")


def current_model(store, session, chats=None):
    require_scope(session, chats)
    return session["fixed"]["model"] if session["fixed"] else document(store, session, chats)


def label_text(labels, say):
    return " · ".join(say(LABEL_NAMES[label]) for label in labels if label in LABEL_NAMES)


def video_clock(video):
    shown = clock(video.get("offset_seconds") or 0)
    return shown + (" · #" + str(video["recording"]) if video.get("recording", 1) > 1 else "")


def video_text(mark, say):
    video = mark.get("video")
    if not video:
        return ""
    return say("Recorder video ≈ {at} from the start of recording (segments of about 10 s; recorder clock).",
               at=clock(video["offset_seconds"]))


def step_line(step, say, clock=action_protocol.same):
    if step.get("hidden"):
        return say("Content hidden: {reasons}. The signed journal keeps the original record.",
                   reasons=", ".join(say(r) for r in step["hidden"]))
    return action_protocol.sentence(step, say, clock)


def cover_rows(known, fixed, say, clock):
    key = signer(fixed)
    rows = [(say("Status"), status_text(fixed, say))]
    if key:
        rows.append((say("Signature"), say("Signed with the workspace key {fingerprint}.", fingerprint=key)))
    if known["from"]:
        rows.append((say("Period"), clock(known["from"]) + " – " + clock(known["to"])))
    return rows


def render_html(model, say=action_protocol.plain_say, fixed=None, images=None, appearance=None):
    appearance = appearance or Appearance()
    model = shaped(model, appearance)
    clock = lambda value: shown_time(value, appearance)
    images = images if appearance.images == "inline" else None
    session, known, key, episodes = model["session"], facts(model), signer(fixed), model["episodes"]
    anchors = {episode["chat_id"]: index for index, episode in enumerate(episodes)}
    toc = ['<a href="#top">' + icon("book") + e(say("Overview")) + "</a>",
           '<a href="#timeline">' + icon("list") + e(say("Timeline")) + "</a>"]
    toc += ['<a class="sub" href="#e' + str(index) + '">' + icon("shield" if episode["chat_id"] is None else "message")
            + e(action_protocol.episode_title(episode, say)) + "</a>" for index, episode in enumerate(episodes)]
    items, blocks, appendix, seen, current, number = [], [], [], set(), object(), 0
    for block in model["blocks"]:
        if block["type"] == "mark":
            items.append('<li class="item note"><span class="dot"></span>' + note_card(block["mark"], say, clock) + "</li>")
            continue
        step, chat = block["step"], block["chat_id"]
        index = anchors.get(chat)
        episode = episodes[index] if index is not None else {}
        skip = appearance.detail == "compact" and action_protocol.minor(step)
        if index is not None and chat != current and (chat not in seen or not skip):
            first, current = chat not in seen, chat
            seen.add(chat)
            items.append('<li class="divider' + ("" if first else " cont") + '"' + (' id="e' + str(index) + '"' if first else "")
                         + '><div class="ep">' + icon("shield" if chat is None else "message") + '<div><div class="kicker">'
                         + e(episode_kind(episode, say)) + "</div><h2>" + e(action_protocol.episode_title(episode, say))
                         + "</h2>" + ("<p>" + e(action_protocol.overview(episode, say, clock)) + "</p>" if first else "")
                         + "</div></div></li>")
        if skip:
            continue
        number += 1
        ref, reference = step.get("ref") or {}, ""
        if ref.get("seq") and appearance.references:
            appendix.append((number, ref["seq"], ref.get("hash") or ""))
            reference = e(say("Journal record #{seq}", seq=ref["seq"])) + (
                "" if appearance.hashes == "appendix" else " · <code>" + e(shown_hash(ref.get("hash"), appearance)) + "</code>")
        items.append(step_item(step, episode, number, say, clock, appearance, images, reference))
    if model["conclusions"]:
        toc.append('<a href="#conclusions">' + icon("flag") + e(say("Conclusions")) + "</a>")
        blocks.append('<section class="block" id="conclusions"><h2>' + icon("flag") + e(say("Conclusions")) + '</h2><p class="lead">'
                      + e(say("Notes and conclusions are the investigator's statements, not Telegram observations."))
                      + '</p><div class="concl">' + "".join(
                          '<div class="concl-card"><div class="num">' + str(n) + "</div><div><p>" + e(m["text"]) + "</p><small>"
                          + e(clock(m["at"])) + (" " + e(say("(cites journal record #{seq})", seq=m["target_seq"]))
                                                 if m.get("target_seq") else "") + "</small></div></div>"
                          for n, m in enumerate(model["conclusions"], 1)) + "</div></section>")
    found = indicator_items(model) if appearance.found else []
    if found:
        numbers = {seq: n for n, seq, _ in appendix}
        toc.append('<a href="#found">' + icon("search") + e(say("Found in messages")) + "</a>")
        blocks.append('<section class="block" id="found"><h2>' + icon("search") + e(say("Found in messages"))
                      + '</h2><p class="lead">'
                      + e(say("Strings found in the messages above. Who controls them is a separate question.")) + "</p>"
                      "<table><tr><th>" + e(say("Kind")) + "</th><th>" + e(say("Value")) + "</th><th>" + e(say("Steps"))
                      + "</th></tr>" + "".join(
                          '<tr><td><span class="kind k-' + e(item["kind"]) + '">' + e(say(item["kind"])) + "</span>"
                          + (" " + e(item["chain"]) if item.get("chain") else "") + '</td><td><span class="mono">'
                          + e(item["value"]) + "</span></td><td>" + ", ".join(
                              '<a href="#s' + str(n) + '">' + str(n) + "</a>"
                              for n in dict.fromkeys(numbers[r["seq"]] for r in item["refs"] if r.get("seq") in numbers))
                          + "</td></tr>" for item in found) + "</table></section>")
    if appearance.hashes == "appendix" and appendix:
        toc.append('<a href="#records">' + icon("key") + e(say("Record references")) + "</a>")
        blocks.append('<section class="block" id="records"><h2>' + icon("key") + e(say("Record references"))
                      + "</h2><table><tr><th>" + e(say("Step")) + "</th><th>" + e(say("Journal record"))
                      + "</th><th>SHA-256</th></tr>" + "".join(
                          '<tr><td><a href="#s' + str(n) + '">' + str(n) + "</a></td><td>#" + e(seq) + "</td><td><code>"
                          + e(value) + "</code></td></tr>" for n, seq, value in appendix) + "</table></section>")
    if model["limits"]:
        toc.append('<a href="#howto">' + icon("help") + e(say("How to read this document")) + "</a>")
        blocks.append('<section class="block howto" id="howto"><h2>' + icon("book") + e(say("How to read this document"))
                      + "</h2><ul>" + "".join("<li>" + icon("check") + "<span>" + e(say(limit)) + "</span></li>"
                                              for limit in model["limits"]) + "</ul></section>")
    state = say("Signed document") if fixed else say("Draft")
    badges = ('<span class="pill ok">' + icon("check", "icon s") + e(say("Fixed and signed")) + "</span>" if fixed
              else '<span class="pill draft">' + icon("alert", "icon s") + e(say("Draft")) + "</span>")
    if key:
        badges += ('<span class="pill sig">' + icon("key", "icon s") + e(say("Key {fingerprint}", fingerprint=key[:16] + "…"))
                   + "</span>")
    if known["hidden"]:
        badges += ('<span class="pill hide">' + icon("lock", "icon s")
                   + e(say("{n} hidden for a stated reason", n=known["hidden"])) + "</span>")
    rows = cover_rows(known, fixed, say, clock) + [
        (say("Time zone"), zone_name(appearance.offset_minutes)), (say("Revision"), session.get("revision") or 1),
        (say("Document"), session["id"])]
    cover = ('<header class="cover"><div class="brand">' + icon("shield") + "TgWitness · " + e(say("Investigation record"))
             + "</div><h1>" + e(session["title"]) + "</h1>"
             + ('<p class="purpose">' + e(session["purpose"]) + "</p>" if session["purpose"] else "")
             + '<div class="badges">' + badges + '</div><dl class="meta">'
             + "".join("<dt>" + e(name) + "</dt><dd>" + e(value) + "</dd>" for name, value in rows) + "</dl>"
             + (cards_html(summary_cards(known, say)) if appearance.summary else "") + "</header>")
    timeline = ('<section class="block" id="timeline"><h2>' + icon("list") + e(say("Timeline")) + '</h2><p class="lead">'
                + e(say("Every step in the order it was recorded: when it was saved, how long after the investigator's "
                        "action it came and which journal record it cites.")) + '</p><ol class="timeline">'
                + "".join(items) + "</ol></section>" if items else "")
    title = session["title"] if len(session["title"]) <= 90 else session["title"][:89] + "…"
    box = ";font:8pt " + FONT + ";color:#8a95a5}"
    paper = ("@page{size:A4;margin:16mm 14mm 18mm;@top-left{content:" + css_string(title) + box + "@top-right{content:"
             + css_string(state) + box + "@bottom-left{content:" + css_string("TgWitness · " + say("Investigation record"))
             + box + '@bottom-right{content:counter(page) " / " counter(pages)' + box + "}"
             "@media print{:root{color-scheme:light;" + PALETTES["light"] + "}" + PRINT + "}")
    nav = ('<nav><div class="brand">' + icon("shield") + 'TgWitness</div><div class="nav-title">' + e(session["title"])
           + '</div><div class="nav-sub">' + e(state) + "</div>" + "".join(toc) + "</nav>")
    return (page_start(say, session["title"], appearance.theme, STYLE + paper) + '<div class="shell">' + nav
            + '<main id="top">' + cover + timeline + "".join(blocks) + '<footer class="doc-foot"><span>TgWitness · '
            + e(say("Investigation record")) + "</span><span>" + e(status_text(fixed, say)) + "</span></footer></main></div></html>")


SLIDES = (
    "*{box-sizing:border-box}html{scroll-snap-type:y mandatory;background:var(--page)}body{margin:0;padding:2vh 0;"
    "color:var(--fg);font-family:" + FONT + ";-webkit-font-smoothing:antialiased}"
    ".mono,code{font-family:" + MONO + ";font-size:.9em;overflow-wrap:anywhere}"
    ".slide{position:relative;width:min(96vw,170.6vh);aspect-ratio:16/9;margin:0 auto 2vh;container-type:size;"
    "overflow:hidden;background:var(--surface);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);"
    "scroll-snap-align:center}.frame{position:absolute;inset:0;display:flex;flex-direction:column;"
    "padding:4cqw 5.2cqw 0;font-size:1.5cqw;line-height:1.42}.body{flex:1;min-height:0;display:flex;"
    "flex-direction:column;justify-content:center;gap:.9em;padding:.6em 0 1em}"
    ".icon{width:1.1em;height:1.1em;flex:none;vertical-align:-.17em}.icon.s{width:.95em;height:.95em}"
    ".kicker{font-size:.7em;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--accent)}"
    "h1{font-size:3.1em;line-height:1.05;letter-spacing:-.03em;margin:.2em 0 .25em;max-width:21em}"
    "h2{font-size:2em;line-height:1.12;letter-spacing:-.02em;margin:.15em 0 0}"
    ".lead{color:var(--muted);font-size:.86em;margin:.35em 0 0;max-width:60em}"
    "footer{display:flex;align-items:center;gap:1.4em;height:3.6em;flex:none;border-top:1px solid var(--line);"
    "font-size:.6em;color:var(--ref)}footer .mark{display:flex;gap:.4em;align-items:center;font-weight:700;"
    "letter-spacing:.1em;text-transform:uppercase;color:var(--accent)}footer .grow{flex:1;overflow:hidden;"
    "white-space:nowrap;text-overflow:ellipsis}footer .n{font-variant-numeric:tabular-nums;font-weight:700}"
    ".slide.cover{background:radial-gradient(110% 130% at 0% 0%,#1e3a8a 0%,#0c1633 52%,#070b18 100%);color:#f4f7ff;"
    "border-color:#1a2550}.slide.cover .kicker{color:#93c5fd}.slide.cover .lead{color:#c7d2fe;font-size:1.05em}"
    ".slide.cover footer{border-color:rgba(255,255,255,.14);color:#94a3c7}.slide.cover footer .mark{color:#93c5fd}"
    ".glow{position:absolute;right:-14cqw;top:-20cqw;width:62cqw;height:62cqw;border-radius:50%;"
    "background:radial-gradient(circle,rgba(139,92,246,.5),rgba(59,130,246,.18) 45%,transparent 68%)}"
    ".seal{position:absolute;right:7cqw;top:6.5cqw;width:11cqw;height:11cqw;color:rgba(255,255,255,.88)}"
    ".badges{display:flex;flex-wrap:wrap;gap:.6em;margin-top:.4em}.pill{display:inline-flex;gap:.45em;align-items:center;"
    "border-radius:999px;padding:.3em .9em;font-size:.72em;font-weight:600;background:rgba(255,255,255,.1);"
    "border:1px solid rgba(255,255,255,.22);color:#fff}"
    ".facts{display:grid;grid-template-columns:auto 1fr;gap:.4em 1.4em;margin:1em 0 0;font-size:.66em;max-width:70em}"
    ".facts dt{color:#93a4cf}.facts dd{margin:0;color:#eef2ff;overflow-wrap:anywhere}"
    ".cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1em}.card{background:var(--surface-2);"
    "border:1px solid var(--line);border-radius:1em;padding:1em 1.1em;display:flex;flex-direction:column;gap:.3em}"
    ".card .icon{color:var(--accent);width:1.4em;height:1.4em}.card b{font-size:2.3em;line-height:1.05;"
    "letter-spacing:-.03em;font-variant-numeric:tabular-nums}.card span{color:var(--muted);font-size:.78em}"
    ".card.alert .icon,.card.alert b{color:var(--warn)}"
    ".slide.chapter .frame{padding-left:9cqw}.slide.chapter:before{content:\"\";position:absolute;left:0;top:0;bottom:0;"
    "width:1.2cqw;background:linear-gradient(var(--accent),var(--violet))}.index{position:absolute;right:5cqw;top:3cqw;"
    "font-size:9em;font-weight:800;letter-spacing:-.05em;line-height:1;color:var(--accent-soft)}"
    ".slide.chapter .cards{margin-top:1em}.slide.chapter .card b{font-size:1.8em}"
    ".chat{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:.7em}.dot{display:none}"
    ".row-meta{display:flex;flex-wrap:wrap;gap:.3em .7em;align-items:center;font-size:.62em;color:var(--muted);"
    "margin-bottom:.3em}.row-meta .no{font-weight:700;color:var(--fg)}.item.msg.out .row-meta{justify-content:flex-end}"
    "time{font-variant-numeric:tabular-nums}.chip{display:inline-flex;gap:.35em;align-items:center;border-radius:999px;"
    "padding:.08em .7em;font-weight:600;background:var(--surface-2);border:1px solid var(--line)}"
    ".chip.lag{background:var(--lag-soft);color:var(--lag);border-color:transparent}"
    ".chip.video{background:var(--blue-soft);color:var(--blue);border-color:transparent;font-family:var(--mono)}"
    ".bubble{max-width:74%;border-radius:1em;padding:.5em .85em .55em;background:var(--bubble-in);"
    "border:1px solid var(--line)}.bubble.in{border-top-left-radius:.3em}.bubble.bot{background:var(--bubble-bot);"
    "border-color:var(--bot-line)}.bubble.out{margin-left:auto;background:var(--bubble-out);"
    "border-color:var(--accent-line);border-top-right-radius:.3em}.who{font-size:.68em;font-weight:700;color:var(--blue)}"
    ".bubble.bot .who{color:var(--bot)}.bubble.out .who{color:var(--accent)}.who .tags{font-weight:500;"
    "color:var(--muted);margin-left:.6em}.text{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.9em}"
    ".long .text{font-size:.68em}.buttons{display:flex;gap:.4em;margin-top:.45em}.buttons span{flex:1 1 auto;"
    "text-align:center;font-size:.66em;font-weight:600;padding:.3em .6em;border-radius:.6em;background:var(--surface);"
    "border:1px solid var(--line);color:var(--accent)}.media{display:flex;gap:.4em;align-items:center;font-size:.62em;"
    "color:var(--muted);margin-top:.3em}"
    ".sys-line{display:flex;gap:.6em;align-items:flex-start;font-size:.76em;background:var(--surface-2);"
    "border:1px solid var(--line);border-radius:.8em;padding:.45em .8em;overflow-wrap:anywhere}"
    ".sys-line .icon{color:var(--muted);margin-top:.15em}.item.alert .sys-line .icon{color:var(--warn)}"
    ".hidden-box{display:flex;gap:.6em;align-items:center;background:var(--warn-soft);color:var(--warn);"
    "border:1px dashed var(--warn-line);border-radius:.8em;padding:.5em .9em;font-weight:600;font-size:.76em}"
    ".callout{display:flex;gap:.6em;align-items:flex-start;margin-top:.4em;border-radius:.8em;padding:.4em .8em;"
    "font-size:.66em;border:1px solid var(--warn-line);background:var(--warn-soft);max-width:74%;overflow-wrap:anywhere}"
    ".item.msg.out .callout{margin-left:auto}.callout .icon{color:var(--warn);margin-top:.1em}.callout b{display:block;"
    "color:var(--warn);font-size:.85em;letter-spacing:.06em;text-transform:uppercase}.callout .mono{display:block}"
    ".capture{display:grid;grid-template-columns:1.6fr 1fr;gap:2.2em;align-items:center}.capture.solo{"
    "grid-template-columns:1fr}figure.shot{margin:0;border:1px solid var(--line);border-radius:.9em;overflow:hidden;"
    "background:var(--surface);box-shadow:var(--shadow)}.chrome{display:flex;gap:.4em;align-items:center;"
    "padding:.45em .8em;background:var(--surface-2);border-bottom:1px solid var(--line);font-size:.6em;"
    "color:var(--muted)}.chrome i{width:.8em;height:.8em;border-radius:50%;background:var(--line)}"
    ".chrome i:nth-child(1){background:#f87171}.chrome i:nth-child(2){background:#fbbf24}"
    ".chrome i:nth-child(3){background:#34d399}.chrome span{margin-left:.6em;overflow:hidden;text-overflow:ellipsis;"
    "white-space:nowrap}figure.shot img{display:block;width:100%;max-height:28cqw;object-fit:contain;"
    "object-position:top;background:var(--surface-2)}figure.shot figcaption{padding:.35em .8em;font-size:.52em;"
    "color:var(--ref);border-top:1px solid var(--line);overflow-wrap:anywhere}"
    ".specs{display:grid;grid-template-columns:auto 1fr;gap:.5em 1em;margin:0;font-size:.7em}.specs dt{color:var(--muted)}"
    ".specs dd{margin:0;font-weight:600;overflow-wrap:anywhere}.caveat{font-size:.6em;color:var(--muted);margin:1em 0 0;"
    "border-left:3px solid var(--amber);padding-left:.8em}"
    ".notes{display:grid;grid-template-columns:1fr 1fr;gap:1em}.note-card{border-radius:1em;padding:.8em 1em;"
    "background:var(--surface-2);border:1px solid var(--line);border-left:.35em solid var(--muted)}"
    ".note-card.important{border-left-color:var(--amber)}.note-card.question{border-left-color:var(--violet)}"
    ".note-card.conclusion{border-left-color:var(--blue)}.note-card.hide{border-left-color:var(--warn)}"
    ".note-card.decision{border-left-color:var(--accent)}.label.decision{background:var(--surface-2);color:var(--accent)}"
    ".labels{display:flex;flex-wrap:wrap;gap:.5em;align-items:center;font-size:.6em;color:var(--muted)}"
    ".label{border-radius:999px;padding:.1em .8em;font-weight:700;background:var(--surface);color:var(--fg)}"
    ".label.important{background:var(--amber-soft);color:var(--amber)}.label.question{background:var(--violet-soft);"
    "color:var(--violet)}.label.conclusion{background:var(--blue-soft);color:var(--blue)}.label.hide{"
    "background:var(--warn-soft);color:var(--warn)}.note-text{white-space:pre-wrap;margin-top:.4em;font-size:.86em;"
    "overflow-wrap:anywhere}.note-card .ref{font-size:.58em;color:var(--ref);margin-top:.4em}"
    "table{border-collapse:separate;border-spacing:0;width:100%;font-size:.7em;border:1px solid var(--line);"
    "border-radius:.8em;overflow:hidden}td,th{padding:.45em .8em;border-bottom:1px solid var(--line);text-align:left;"
    "vertical-align:top;overflow-wrap:anywhere}th{background:var(--surface-2);color:var(--muted);font-size:.85em;"
    "letter-spacing:.06em;text-transform:uppercase}tr:last-child td{border-bottom:0}.kind{display:inline-block;"
    "border-radius:.4em;padding:.05em .6em;font-weight:700;background:var(--surface-2)}.k-wallet{"
    "background:var(--amber-soft);color:var(--amber)}.k-url,.k-domain{background:var(--blue-soft);color:var(--blue)}"
    ".k-telegram,.k-telegram-invite{background:var(--accent-soft);color:var(--accent)}.k-email,.k-phone{"
    "background:var(--violet-soft);color:var(--violet)}.more{font-size:.62em;color:var(--muted);margin:0}"
    ".concl{display:grid;gap:.8em}.concl-card{display:grid;grid-template-columns:2.2em 1fr;gap:1em;align-items:start;"
    "background:var(--blue-soft);border:1px solid var(--blue-line);border-radius:1em;padding:.9em 1.1em}"
    ".concl-card .num{width:2.2em;height:2.2em;border-radius:.6em;background:var(--blue);color:var(--surface);"
    "display:grid;place-items:center;font-weight:800}.concl-card p{margin:0;font-size:1.02em;font-weight:500;"
    "white-space:pre-wrap;overflow-wrap:anywhere}.concl-card small{display:block;margin-top:.3em;font-size:.6em;"
    "color:var(--muted)}.verify{display:grid;grid-template-columns:1fr 1.3fr;gap:2.2em;align-items:start}"
    ".proof{background:var(--ok-soft);border:1px solid var(--ok-line);border-radius:1em;padding:1.1em 1.2em}"
    ".proof.draft{background:var(--amber-soft);border-color:var(--amber-line)}.proof>.icon{width:2.2em;height:2.2em;"
    "color:var(--ok)}.proof.draft>.icon{color:var(--amber)}.proof .specs{margin-top:.8em;font-size:.6em}"
    ".proof .specs dd{font-weight:500}.limits{list-style:none;margin:0;padding:0;display:grid;gap:.55em}"
    ".limits li{display:flex;gap:.6em;align-items:flex-start;font-size:.7em}.limits .icon{color:var(--accent);"
    "margin-top:.15em}"
    "@page{size:13.333in 7.5in;margin:0}@media print{html{scroll-snap-type:none;background:none}body{padding:0}"
    ".slide{width:13.333in;height:7.5in;aspect-ratio:auto;margin:0;border:0;border-radius:0;box-shadow:none;"
    "break-after:page}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}")
SLIDES += SUBJECT_CSS


def weight(step, say):
    if step.get("hidden"):
        return 0.8
    if step["type"] not in MESSAGE_TYPES:
        return 0.8 + len(step_line(step, say)) / 500
    return (1 + len(step.get("text") or "") / 300 + 0.35 * len(step.get("buttons") or [])
            + 0.25 * bool(step.get("media") or step.get("files"))
            + 0.6 * (len(step.get("deceptive_links") or []) + len(step.get("risky_links") or [])))


def capture_html(step, say, clock, images):
    first = next((item for item in step.get("files") or [] if (images or {}).get(item["sha256"])), None)
    picture = shots({"files": [first]}, images, say, step.get("final_url") or step.get("url")) if first else ""
    seq = (step.get("ref") or {}).get("seq")
    specs = [(say("Opened"), step.get("url")),
             (say("Ended at"), step.get("final_url") if step.get("final_url") != step.get("url") else None),
             (say("Page title"), step.get("title")), (say("HTTP status"), step.get("http_status")),
             (say("Server address"), step.get("server_ip")), (say("Certificate issuer"), step.get("issuer")),
             (say("Captured"), clock(step.get("at"))), (say("Journal record"), "#" + str(seq) if seq else None)]
    subject = step.get("subject") or {}
    shown = " · ".join(str(value) for value in (subject.get("title"), subject.get("telegram"),
                                                 "ID " + str(subject["chat_id"]) if subject.get("chat_id") is not None
                                                 else None) if value)
    notes = ([say("Requested as the view of {who}; this caption comes from the workspace records, not from the "
                  "screenshot.", who=shown)] if shown else []) + (
        [say("Not captured: {parts}.", parts=", ".join(step["errors"]))] if step.get("errors") else [])
    return ('<div class="capture' + ("" if picture else " solo") + '">' + picture + '<div><dl class="specs">'
            + "".join("<dt>" + e(name) + "</dt><dd>" + e(value) + "</dd>" for name, value in specs if value)
            + "</dl>" + "".join('<p class="caveat">' + e(note) + "</p>" for note in notes) + "</div></div>")


def render_slides(model, say=action_protocol.plain_say, fixed=None, images=None, appearance=None):
    appearance = appearance or Appearance()
    model = shaped(model, appearance)
    clock = lambda value: shown_time(value, appearance)
    images = images if appearance.images == "inline" else None
    session, known, key = model["session"], facts(model), signer(fixed)
    state = say("Signed document") if fixed else say("Draft")
    numbers, count, slides = {}, 0, []
    for block in model["blocks"]:
        if block["type"] == "step" and not (appearance.detail == "compact" and action_protocol.minor(block["step"])):
            count += 1
            numbers[id(block["step"])] = count

    def slide(kicker, title, content, lead=""):
        slides.append(("", '<div class="head"><div class="kicker">' + e(kicker) + "</div><h2>" + e(title) + "</h2>"
                       + ('<p class="lead">' + e(lead) + "</p>" if lead else "") + '</div><div class="body">' + content
                       + "</div>"))

    badge = ('<span class="pill">' + icon("check" if fixed else "alert", "icon s")
             + e(say("Fixed and signed") if fixed else say("Draft")) + "</span>")
    slides.append(("cover", '<div class="glow"></div>' + icon("shield", "seal") + '<div class="body"><div class="kicker">'
                   "TgWitness · " + e(say("Investigation record")) + "</div><h1>" + e(session["title"]) + "</h1>"
                   + ('<p class="lead">' + e(session["purpose"]) + "</p>" if session["purpose"] else "")
                   + '<div class="badges">' + badge + '</div><dl class="facts">'
                   + "".join("<dt>" + e(name) + "</dt><dd>" + e(value) + "</dd>"
                             for name, value in cover_rows(known, fixed, say, clock)) + "</dl></div>"))
    slide(say("Overview"), say("What this record contains"), cards_html(summary_cards(known, say)))
    for index, episode in enumerate(model["episodes"], 1):
        title, summary = action_protocol.episode_title(episode, say), episode.get("summary") or {}
        first = summary.get("first_reply_seconds")
        risky = summary.get("risky_links", 0) + summary.get("deceptive_links", 0)
        tiles = [("message", summary.get("replies", 0), say("replies or edits"), False),
                 ("timer", say("{n} s", n=action_protocol.pretty(first)) if first is not None else "—",
                  say("fastest reply"), False), ("trash", summary.get("deletions", 0), say("deletion notices"), False),
                 ("alert", risky, say("risky or deceptive links"), bool(risky))]
        slides.append(("chapter", '<div class="index">' + "%02d" % index + '</div><div class="body"><div><div class="kicker">'
                       + e(episode_kind(episode, say)) + "</div><h1>" + e(title) + '</h1><p class="lead">'
                       + e(action_protocol.overview(episode, say, clock)) + "</p></div>"
                       + (cards_html(tiles) if summary.get("actions") or summary.get("replies") else "") + "</div>"))
        pages, page, load = [], [], 0.0
        for step in (b["step"] for b in model["blocks"] if b["type"] == "step" and b["chat_id"] == episode["chat_id"]
                     and not action_protocol.minor(b["step"])):
            if step["type"] == "visual" and not step.get("hidden"):
                pages += [page, step] if page else [step]
                page, load = [], 0.0
                continue
            size = weight(step, say)
            if page and load + size > 4.2:
                pages.append(page)
                page, load = [], 0.0
            page.append(step)
            load += size
        if page:
            pages.append(page)
        for page in pages:
            if isinstance(page, dict):
                slide(title, say("Isolated browser capture"), capture_html(page, say, clock, images))
                continue
            start, end = clock(page[0].get("at")), clock(page[-1].get("at"))
            span = start + (" – " + end if end != start else "")
            slide(say("Timeline"), title, '<ol class="chat">' + "".join(
                step_item(step, episode, numbers.get(id(step), "?"), say, clock, appearance, images, slim=True)
                for step in page) + "</ol>", span)
    notes = [m for m in (b["mark"] for b in model["blocks"] if b["type"] == "mark")
             if {"important", "question"} & set(m["labels"])]
    for start in range(0, len(notes), 6):
        slide(say("Notes"), say("Important points and open questions"),
              '<div class="notes">' + "".join(note_card(m, say, clock) for m in notes[start:start + 6]) + "</div>")
    found = indicator_items(model) if appearance.found else []
    if found:
        slide(say("Found in messages"), say("Wallets, links, domains and accounts"), "<table>" + "".join(
            '<tr><td><span class="kind k-' + e(item["kind"]) + '">' + e(say(item["kind"])) + "</span>"
            + (" " + e(item["chain"]) if item.get("chain") else "") + '</td><td><span class="mono">' + e(item["value"])
            + "</span></td></tr>" for item in found[:12]) + "</table>"
              + ('<p class="more">' + e(say("{n} more in the full report.", n=len(found) - 12)) + "</p>"
                 if len(found) > 12 else ""),
              say("Strings found in the messages above. Who controls them is a separate question."))
    conclusions = model["conclusions"]
    for start in range(0, len(conclusions), 4):
        slide(say("Conclusions"), say("What the investigator concludes"), '<div class="concl">' + "".join(
            '<div class="concl-card"><div class="num">' + str(n) + "</div><div><p>" + e(m["text"]) + "</p><small>"
            + e(clock(m["at"])) + (" " + e(say("(cites journal record #{seq})", seq=m["target_seq"]))
                                   if m.get("target_seq") else "") + "</small></div></div>"
            for n, m in enumerate(conclusions[start:start + 4], start + 1)) + "</div>",
              say("Notes and conclusions are the investigator's statements, not Telegram observations."))
    proof = [(say("Workspace key"), key), (say("Statement SHA-256"), (fixed or {}).get("statement_sha256")),
             (say("Recorded in journal record"), "#" + str(fixed["event_seq"]) if fixed and fixed.get("event_seq") else None)]
    slide(say("Verification"), say("How to check this record"),
          '<div class="verify"><div class="proof' + ("" if fixed else " draft") + '">' + icon("shield" if fixed else "alert")
          + '<div class="kicker">' + e(state) + '</div><dl class="specs">'
          + "".join("<dt>" + e(name) + '</dt><dd class="mono">' + e(value) + "</dd>" for name, value in proof if value)
          + "</dl>" + ("" if fixed else '<p class="caveat">' + e(status_text(fixed, say)) + "</p>") + "</div>"
          '<ul class="limits">' + "".join("<li>" + icon("check") + "<span>" + e(say(limit)) + "</span></li>"
                                          for limit in model["limits"][:5]) + "</ul></div>",
          say("The case package contains the signed original and step-by-step checks."))
    total = len(slides)
    return (page_start(say, session["title"], appearance.theme, SLIDES) + "".join(
        '<section class="slide' + (" " + kind if kind else "") + '"><div class="frame">' + content
        + '<footer><span class="mark">' + icon("shield", "icon s") + 'TgWitness</span><span class="grow">'
        + e(session["title"]) + "</span><span>" + e(state) + '</span><span class="n">' + str(n) + " / " + str(total)
        + "</span></footer></div></section>" for n, (kind, content) in enumerate(slides, 1)) + "</html>")


def render_markdown(model, say=action_protocol.plain_say, fixed=None, appearance=None):
    escape = lambda value: str(value).replace("\r", "").replace("\n", "\n> ")
    appearance = appearance or Appearance()
    model = shaped(model, appearance)
    session = model["session"]
    lines = ["# " + session["title"], ""]
    if session["purpose"]:
        lines += [session["purpose"], ""]
    lines += ["_" + (say("Fixed document. Statement SHA-256: {digest}", digest=fixed["statement_sha256"]) if fixed
                     else say("Draft. Not signed; it can still change.")) + "_", ""]
    seen, number = set(), 0
    titles = {episode["chat_id"]: episode for episode in model["episodes"]}
    for block in model["blocks"]:
        if block["type"] == "mark":
            mark = block["mark"]
            lines += ["> **" + (label_text(mark["labels"], say) or say("Note")) + "** · " + shown_time(mark["at"], appearance),
                      "> " + escape(mark["text"])]
            if mark.get("video"):
                lines.append("> _" + video_text(mark, say) + "_")
            lines.append("")
            continue
        step, chat = block["step"], block["chat_id"]
        if chat not in seen and chat in titles:
            seen.add(chat)
            episode = titles[chat]
            lines += ["## " + action_protocol.episode_title(episode, say), "",
                      action_protocol.overview(episode, say, lambda value: shown_time(value, appearance)), ""]
        number += 1
        lag = action_protocol.delay(step, say)
        ref = step.get("ref") or {}
        lines.append(str(number) + ". `" + shown_time(step.get("at"), appearance) + "`" + (" (" + lag + ")" if lag else "")
                     + " — " + step_line(step, say, lambda value: shown_time(value, appearance)).replace("\n", " ")
                     + (" — " + say("record #{seq}", seq=ref["seq"]) + " `" + shown_hash(ref.get("hash"), appearance) + "`"
                        if ref.get("seq") else ""))
        if step.get("translation") and not step.get("hidden"):
            lines.append("   > _" + translation_label(step["translation"], say) + ":_ "
                         + step["translation"]["text"].replace("\n", " "))
    if model["conclusions"]:
        lines += ["", "## " + say("Conclusions"), ""]
        lines += ["- " + m["text"].replace("\n", " ") for m in model["conclusions"]]
    if model["limits"]:
        lines += ["", "## " + say("How to read this document"), ""] + ["- " + say(limit) for limit in model["limits"]]
    return "\n".join(lines) + "\n"
