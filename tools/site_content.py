"""Explicit public guide and reference inventory. No runtime application dependency."""

GUIDES = {
    "archive": ("Work the archive", "Load history, search saved records, review AI sources and connect your tools.", "archive history search AI MCP OCR transcription webhooks reports integrations", "docs/ANALYSIS.md"),
    "capture": ("GitHub Actions capture", "Export one Telegram chat on a temporary GitHub runner.", "github actions capture encrypted archive", "docs/SEALED-ACTIONS.md"),
    "dedicated-account": ("Dedicated account", "Prepare a separate Telegram account for collection.", "dedicated telegram account session api login", "docs/ACCOUNTS.md"),
    "start": ("Start in minutes", "Try TgWitness with sample data, then launch your own Telegram observation workspace on Windows, Linux or macOS.", "demo install setup windows linux macos python", "docs/QUICKSTART.md"),
    "accounts": ("Connect an account", "Connect Telegram by QR code, phone number or session import. Choose sources and check that new messages reach your journal.", "qr phone session tdata api id hash account sources", "docs/ACCOUNTS.md"),
    "proxies": ("Choose a proxy", "Maintain automatic MTProxy routes or use your own proxy. Choose IP modes, fallback rules and the route for external requests.", "mtproto mtproxy socks5 http automatic pool IP modes fallback network public lists", "docs/CONNECTION-SECURITY.md"),
    "exports": ("Export and verify", "Export captured Telegram history, verify signatures and compare a journal with a checkpoint retained by an independent witness.", "evidence signature hash integrity verify zip fingerprint checkpoint s3 backup restore recovery object lock", "docs/EVIDENCE.md"),
    "concepts": ("See how evidence works", "Follow a message from capture to checkpoint. Change a sample record, recalculate its SHA-256 chain and see what a retained checkpoint detects.", "visual animation diagram formula sha256 hash chain canonical signature tamper learn", "docs/HOW-IT-WORKS.md"),
    "cases": ("Investigate across all chats", "Run an end-to-end Telegram investigation across channels, groups, private chats and bots: whole-account capture, history, people, links, files, timelines and verified evidence.", "use cases scenarios investigation all chats whole account history dossier people links files timeline case package", "docs/INVESTIGATION.md"),
    "security": ("Keep it secure", "See where sessions, keys and evidence live, what leaves your machine, what the protections cover and how to harden an installation.", "security threat model secrets vault token encryption hardening privacy vulnerability report", "docs/SECURITY-MODEL.md"),
    "access": ("Share a case", "Give reviewers and analysts access to selected accounts and chats, with separate permissions, session limits and revocable tokens.", "access permissions roles scope reviewer analyst token sessions IP expiry revoke", "docs/ACCESS.md"),
    "witness": ("Set up a witness bot", "Publish signed journal checkpoints to your Telegram channel with a separate witness, its own key and read-only collector access.", "bot botfather telegram channel continuity checkpoint independent witness", "docs/WITNESS.md"),
    "server": ("Keep it running", "Run TgWitness on a server with persistent storage, private panel access, backups and checks after a restart.", "docker compose deployment vps backup restore update restart operations", "docs/DEPLOYMENT.md"),
    "troubleshooting": ("Find what went wrong", "Check panel access, Telegram connection, missing messages, FloodWait and witness status using the right signals for each problem.", "help error token login disconnected floodwait gap pts qts recovery github", "docs/OPERATIONS.md"),
}

GROUPS = (
    ("First steps", "Your first captured message", ("start", "dedicated-account", "accounts", "proxies", "exports", "capture")),
    ("Understand the evidence", "Learn by trying it", ("concepts", "cases", "security")),
    ("Go further", "Add only what you need", ("archive", "access", "witness", "server", "troubleshooting")),
)


REFERENCE = {
    "history": ("Load source history", "Load past messages from enabled sources, pause and resume, and verify a signed progress report.", "history acquisition sources pause resume progress report", "docs/HISTORY.md"),
    "analysis": ("Archive analysis", "Search saved messages, review AI inputs and keep analytical reports with their source references.", "analysis AI Ollama sources citations reports review", "docs/ANALYSIS.md"),
    "mcp": ("Read-only MCP", "Connect an MCP client to selected workspaces and chats with expiring, revocable access.", "MCP integrations stdio Streamable HTTP VS Code token scope", "docs/MCP.md"),
    "media-analysis": ("Local OCR and transcription", "Recognize captured images and audio with a local worker; keep derived text linked to its source file.", "OCR transcription Tesseract Whisper Docker media attachment", "docs/MEDIA-ANALYSIS.md"),
    "webhooks": ("Outgoing webhooks", "Send scoped events to HTTPS receivers with HMAC signatures, retries and delivery status.", "webhooks HMAC n8n SIEM integrations notifications retries", "docs/WEBHOOKS.md"),
    "notice": ("Operator incompatibility notice", "Our operator notice on Taylor Wessing and its source record.", "notice operator incompatibility Taylor Wessing statement licence", "docs/OPERATOR-INCOMPATIBILITY.md"),
    "license": ("Licence and architectural incompatibility notice", "TgWitness is MIT-licensed for everyone, and why it is architecturally incompatible with the Taylor Wessing workflow.", "license licence MIT Taylor Wessing position statement", "docs/TAYLOR-WESSING-EXCLUSION.md"),
    "quickstart": ("Quick start", "Every way to install and launch TgWitness: Windows package, Python, Docker and the synthetic demo, with first checks.", "install launch windows linux macos docker demo setup", "docs/QUICKSTART.md"),
    "accounts": ("Accounts and session formats", "Sign in by phone, QR code or auth key, import Telethon, Pyrogram or Telegram Desktop sessions, and run several accounts.", "login phone qr session tdata pyrogram telethon import api pair", "docs/ACCOUNTS.md"),
    "access": ("Access and permissions", "Issue scoped access to accounts and chats, choose permissions, limit sessions and IP addresses, and withdraw access.", "access permissions scope token session IP expiry revoke admin console", "docs/ACCESS.md"),
    "connection": ("Connection, proxies and data protection", "Authentication, automatic proxy pools, IP modes, fallback policy, external requests and secret storage.", "proxy mtproxy pool socks5 http route IP mode fallback api id hash network", "docs/CONNECTION-SECURITY.md"),
    "deployment": ("Deployment", "Run TgWitness as a service on Windows, Linux, macOS or Docker, behind HTTPS, with backups and updates.", "server docker compose systemd launchd https caddy backup update", "docs/DEPLOYMENT.md"),
    "collection": ("How collection works", "Observation scope, live updates, rechecks, attachments, own actions and what a gap means, record by record.", "scope folder account recheck attachments gaps updates floodwait", "docs/COLLECTION.md"),
    "operations": ("Workflows and operations", "Daily operation of the panel: modes, monitoring categories, parameters, notifications, exports, backup and capacity.", "panel operations parameters notifications backup restore capacity", "docs/OPERATIONS.md"),
    "investigation": ("Investigation mode", "Whole-account investigations across channels, groups, private chats and bots, from scope to a verified case package.", "investigation whole account bots people timeline case", "docs/INVESTIGATION.md"),
    "features": ("Features and limits", "What TgWitness implements today, what the Telegram platform limits and what remains future work.", "features product status roadmap limits platform", "docs/PRODUCT.md"),
    "how-it-works": ("How the evidence works", "Hash chain, signatures, checkpoints and witnesses explained with the exact formulas the verifier uses.", "hash chain sha256 ed25519 canonical json checkpoint formula", "docs/HOW-IT-WORKS.md"),
    "evidence": ("Evidence format", "Contents of the signed ZIP, record kinds, process receipts, people profiles, off-site copies and offline verification.", "evidence zip manifest events jsonl verify dossier replica s3", "docs/EVIDENCE.md"),
    "witness": ("Independent witness", "Run a witness with its own key and bot, publish signed checkpoints to a channel and check exports against it.", "witness bot channel checkpoint tgw1 verify continuity", "docs/WITNESS.md"),
    "timestamp": ("Timestamps", "RFC 3161 timestamps for signed checkpoints: what is sent to the authority and how a response is verified.", "rfc 3161 tsa timestamp authority nonce checkpoint", "docs/TIMESTAMP.md"),
    "security": ("Security and data handling", "Threat model, access model, secrets at rest, network exposure, session imports and how to report a vulnerability.", "security threat model token vault fernet encryption report vulnerability", "docs/SECURITY-MODEL.md"),
    "architecture": ("Architecture", "Components of the collector, panel, journal, workers and witness, and how data moves between them.", "architecture components journal workers sqlite telethon fastapi", "docs/ARCHITECTURE.md"),
    "verification": ("What has been tested", "The live Telegram test, automated checks, browser checks and what remains unverified.", "tests verification live test coverage limitations", "docs/VERIFICATION.md"),
    "changelog": ("Changelog", "Every change by version, including the changes not yet released.", "changelog release notes versions history", "docs/CHANGELOG.md"),
}

REFERENCE_GROUPS = (
    ("Set up", ("quickstart", "accounts", "access", "connection", "deployment")),
    ("Collect", ("collection", "history", "operations", "investigation", "features")),
    ("Archive & integrations", ("analysis", "mcp", "media-analysis", "webhooks")),
    ("Evidence", ("how-it-works", "evidence", "witness", "timestamp")),
    ("Security & project", ("security", "architecture", "verification", "license", "notice", "changelog")),
)

LABELS = {
    "licence_link": "MIT license", "operator_link": "Operator notice",
    "docs": "Documentation", "home": "Home", "skip": "Skip to content", "nav": "Guides",
    "title": "Follow the message. Understand the evidence.",
    "intro": "Get your first capture, explore how the proof works, then build the setup you need.",
    "description": "Get your first capture, explore how the proof works, then build the setup you need.",
    "search": "Search the documentation", "placeholder": "Try proxy, hash chain, token or witness…",
    "empty": "No matches. Try a shorter term or choose a page below.",
    "results": "Pages found:", "prompt": "Type a word to search the guides and the reference. Search stays in your browser.",
    "clear": "Clear search", "toc": "On this page", "reference": "Full reference",
    "next": "Next step", "index": "All guides", "about": "Open source · Runs on your machine",
    "note": "These guides describe the current implementation. Validation results and remaining gaps are documented separately.",
    "verification": "What has been tested", "wiki": "Reference", "source": "Edit this page on GitHub",
    "wiki_title": "The complete reference",
    "wiki_intro": "Every document of the project, rendered here with its diagrams. The guides are the short path; these pages hold every detail.",
}

NEXT = {"archive": "exports", "capture": "exports", "dedicated-account": "accounts", "start": "accounts", "accounts": "exports", "access": "security", "proxies": "accounts", "exports": "concepts",
        "concepts": "cases", "cases": "security", "security": "start", "witness": "server",
        "server": "troubleshooting", "troubleshooting": "start"}
