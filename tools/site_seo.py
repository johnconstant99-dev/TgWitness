import html
import json
import posixpath
import re

if __package__:
    from .site_i18n import LANGUAGES, _Tree
else:
    from site_i18n import LANGUAGES, _Tree


PAGES = {
    "": ("Telegram Chat Export & OSINT Evidence", "Export Telegram chats, preserve observed edits and deletion notices, investigate saved records and verify signed evidence archives with TgWitness.", "Telegram chat export"),
    "docs/": ("Telegram Export, OSINT & Evidence Guides", "Learn to export Telegram chats, investigate saved messages, prepare case reports and verify signed evidence. Setup, account and security guides.", "Telegram export guide"),
    "docs/reference/": ("Telegram Collection & Evidence Technical Reference", "Technical documentation for TgWitness: Telegram collection, signed exports, account sessions, verification, deployment, integrations and access control.", "Telegram evidence documentation"),
    "docs/start/": ("Install TgWitness for Telegram Chat Export", "Install TgWitness on Windows, Linux or macOS, connect a Telegram account and export a signed archive. Start with a fictional demo or your own workspace.", "install Telegram chat exporter"),
    "docs/dedicated-account/": ("Choose a Dedicated Telegram Collection Account", "Prepare a dedicated Telegram account for collection. Review session ownership, login choices and account risks before connecting it to TgWitness.", "dedicated Telegram account"),
    "docs/accounts/": ("Connect Telegram: QR, Phone & Session Import", "Connect Telegram to TgWitness by QR code, phone login or session import. Select chats and confirm that new messages reach the observation journal.", "Telegram session import"),
    "docs/proxies/": ("Telegram Proxies: MTProxy, SOCKS5 & Routing", "Configure Telegram MTProxy, SOCKS5 or HTTP proxy routes in TgWitness. Review automatic pools, IP modes, fallback rules and external-request routing.", "Telegram MTProxy SOCKS5 proxy"),
    "docs/exports/": ("Export Telegram Chats & Verify Signed Evidence", "Export captured Telegram chat history as signed evidence. Check archive signatures, file hashes and independently retained journal checkpoints offline.", "export Telegram chats"),
    "docs/capture/": ("Export Telegram with GitHub Actions Capture", "Run Telegram Takeout, regular API export or chat journaling on a temporary GitHub Actions runner. Download an encrypted archive and workflow provenance.", "Telegram export GitHub Actions"),
    "docs/concepts/": ("Telegram Evidence: Hash Chains & Signatures", "Follow Telegram records through a SHA-256 hash chain, Ed25519 signatures and retained checkpoints. Explore what integrity checks can and cannot prove.", "Telegram evidence hash chain"),
    "docs/cases/": ("Telegram OSINT Investigations Across Chats", "Investigate saved Telegram channels, groups, private chats and bots. Connect people, messages, files and timelines in a verifiable case package.", "Telegram OSINT investigation"),
    "docs/case-board/": ("Telegram Case Board: Evidence & Annotations", "Organize saved Telegram observations, exact highlights and action slices on a Case Board. Link team annotations and presentations to their source records.", "Telegram evidence case board"),
    "docs/reports/": ("Telegram Evidence Reports: HTML & Signed PDF", "Build Telegram case reports from saved records. Choose a layout, preview the selected data and export HTML, signed PDF or a complete evidence package.", "Telegram evidence report"),
    "docs/handover/": ("Share Telegram Evidence with Limited Disclosure", "Prepare a minimized Telegram evidence sharing copy. Choose records and fields, inspect disclosure and verify its manifest against the source journal.", "Telegram evidence sharing copy"),
    "docs/groups/": ("Manage Multiple Telegram Collection Accounts", "Manage TgWitness account groups, compare observation coverage and apply shared settings with per-account exceptions. Keep workspaces and journals separate.", "multiple Telegram accounts collection"),
    "docs/archive/": ("Search & Analyze a Saved Telegram Archive", "Load Telegram history, search captured messages and review source-linked analysis. Connect archive tools for OCR, transcription, MCP and report workflows.", "Telegram archive analysis"),
    "docs/security/": ("Secure Telegram Sessions & Evidence Storage", "Review TgWitness session storage, signing keys, panel access and network exposure. Apply the security model to your Telegram collection workspace.", "Telegram session security"),
    "docs/access/": ("Share Telegram Case Access with Reviewers", "Grant reviewers access to selected Telegram accounts and chats. Set permissions, expiry and session limits, then revoke access when the task ends.", "Telegram evidence reviewer access"),
    "docs/witness/": ("Set Up a Telegram Evidence Witness Bot", "Run an independent witness bot with its own signing key. Publish Telegram journal checkpoints and compare evidence exports with records retained elsewhere.", "Telegram evidence witness bot"),
    "docs/server/": ("Host TgWitness: Telegram Collection Server", "Run TgWitness on a server with persistent evidence storage, private panel access and backups. Check collection and recovery after updates or restarts.", "self hosted Telegram collection"),
    "docs/troubleshooting/": ("Fix Telegram Login, FloodWait & Collection Gaps", "Diagnose Telegram login errors, FloodWait, disconnected collectors and missing observations. Check panel access, journal coverage and witness status.", "Telegram FloodWait troubleshooting"),
    "docs/export-clinic/": ("Telegram Desktop Export: Controlled Experiment", "Inspect a recorded Telegram Desktop export experiment across seven test conversations. Compare paired files, observed results and the original recording.", "Telegram Desktop export comparison"),
    "docs/validation/": ("Telegram Export Benchmarks & Signed Test Results", "Review two Telegram exports totaling 56,329 messages. Compare collection speed, complete export time, test scope and independently verifiable archives.", "Telegram export benchmark"),
    "guides/modes.html": ("Telegram Collection Modes & Evidence Levels", "Compare TgWitness collection scopes, capture methods and verification mechanisms. Choose a workflow using documented limits and fictional investigation cases.", "Telegram collection modes"),
    "docs/reference/overview/": ("TgWitness: Telegram Export, OSINT & Verification", "Explore TgWitness installation, Telegram capture, investigation tools and evidence verification. Read measured workloads alongside their methods and limits.", "TgWitness Telegram OSINT"),
    "docs/reference/quickstart/": ("TgWitness Setup: Windows, Linux, macOS & Docker", "Choose a TgWitness installation method, launch the panel and check your first workspace. Includes Windows, Linux, macOS, Docker and the synthetic demo.", "TgWitness installation"),
    "docs/reference/installation/": ("Install, Verify & Update TgWitness", "Install or update TgWitness with one command. Verify release signatures and SHA-256 hashes, review package options and remove an installation safely.", "TgWitness installer signature verification"),
    "docs/reference/settings/": ("Telegram Collection Setup & TgWitness Settings", "Configure TgWitness setup goals, collection options, connection routes and interface levels. Review account-group defaults and per-account overrides.", "Telegram collection settings"),
    "docs/reference/accounts/": ("Telegram Session Formats: TData & Telethon", "Review supported Telegram login and session formats: phone, QR, Auth Key, Telethon, Pyrogram and TData. Check import limits and session ownership.", "Telegram TData Telethon session import"),
    "docs/reference/access/": ("TgWitness Access Tokens, Scopes & Permissions", "Configure scoped access to Telegram workspaces and chats in TgWitness. Review permissions, token expiry, IP restrictions, session limits and revocation.", "TgWitness access permissions"),
    "docs/reference/connection/": ("Telegram Proxy Routing & Connection Security", "Understand TgWitness proxy pools, IP modes, fallback policy and external-request routing. Review authentication and protection of stored connection secrets.", "Telegram proxy connection security"),
    "docs/reference/deployment/": ("Deploy TgWitness with Docker, HTTPS & Backups", "Deploy a persistent TgWitness collection service with Docker or operating-system services. Configure secure panel access, backups, updates and recovery.", "TgWitness Docker deployment"),
    "docs/reference/high-assurance/": ("Phala Intel TDX: Attested Telegram Collection", "Deploy TgWitness on Phala or a conventional VM. Review Intel TDX quotes, OS measurements, collector identity and independent verification boundaries.", "Phala Intel TDX attestation"),
    "docs/reference/panel/": ("TgWitness Panel: Chats, Journal & Exports", "Navigate TgWitness chats, sources, the signed journal, exports and account controls. Review panel actions, capture status and optional investigation tools.", "TgWitness Telegram panel"),
    "docs/reference/collection/": ("Telegram Collection: Updates, Edits & Deletions", "Read how TgWitness captures Telegram updates, edits and deletion notices. Understand source scope, attachments, rechecks, own actions and observation gaps.", "Telegram edited deleted message logger"),
    "docs/reference/secret-chats/": ("Telegram Secret Chats: Implementation Status", "Review the separate Pseudo-secret implementation and its open defects. Explore the fictional interface without confusing a demo with live protocol support.", "Telegram Secret Chats implementation"),
    "docs/reference/history/": ("Telegram History Backfill & Signed Progress", "Load visible Telegram history from enabled sources, pause or resume backfill and inspect signed progress. Previously missed edits and deletions stay unknown.", "Telegram history backfill"),
    "docs/reference/operations/": ("Operate TgWitness: Monitoring, Export & Recovery", "Manage Telegram collection, notifications and exports in TgWitness. Review daily checks, backup procedures, recovery and capacity limits for each workspace.", "TgWitness operations backup recovery"),
    "docs/reference/investigation/": ("Telegram Investigation Mode & Account Scope", "Configure whole-account Telegram investigation across channels, groups, private chats and bots. Preserve observations and prepare a verifiable case package.", "Telegram investigation mode"),
    "docs/reference/features/": ("TgWitness Features & Telegram Collection Limits", "Review implemented TgWitness collection, multi-account workflows and signed exports. Check platform limits and qualification before relying on a feature.", "TgWitness features Telegram limits"),
    "docs/reference/case-board/": ("Case Board: Source-Linked Telegram Annotations", "Review Case Board bookmarks, highlights, action slices and discussions. Understand scoped access, annotation revisions and links to original Telegram records.", "Telegram source linked annotations"),
    "docs/reference/analysis/": ("Telegram Archive Analysis & Source Citations", "Analyze saved Telegram messages with source-linked reports. Review AI inputs, citations and the distinction between captured observations and interpretation.", "Telegram archive AI analysis"),
    "docs/reference/search/": ("Telegram Archive Full-Text Search", "Search captured Telegram messages by word forms, exact phrases, domains and usernames. Review ranking and how the index stays tied to the signed journal.", "Telegram archive full text search"),
    "docs/reference/mcp/": ("Telegram Archive MCP Server: Read-Only Access", "Connect an MCP client to saved Telegram records through scoped, expiring access. Review supported tools, transports and the read-only archive boundary.", "Telegram archive MCP server"),
    "docs/reference/cli/": ("Telegram Archive CLI: Search & JSONL Export", "Use the TgWitness CLI to search Telegram archives, retrieve context, count activity and export JSON Lines locally or through a scoped connection token.", "Telegram archive CLI JSONL export"),
    "docs/reference/media-analysis/": ("Telegram Media OCR & Audio Transcription", "Extract text from captured Telegram images and audio with local OCR and transcription workers. Keep derived text linked to the original media and record.", "Telegram OCR audio transcription"),
    "docs/reference/webhooks/": ("Telegram Evidence Webhooks: HMAC & Delivery", "Send scoped TgWitness events to HTTPS integrations with HMAC signatures. Configure retries and inspect webhook delivery without exposing unrelated records.", "Telegram evidence webhook HMAC"),
    "docs/reference/showcase/": ("Publish Captured Telegram Channel Evidence", "Share selected saved public-channel messages through scoped showcase links. Review expiry, revocation, signed snapshots and limits of the published material.", "Telegram channel evidence showcase"),
    "docs/reference/how-it-works/": ("Evidence Verification: SHA-256 & Ed25519", "Study the TgWitness evidence chain: canonical records, SHA-256 hashes, Ed25519 signatures, checkpoints and witnesses, with the verifier's exact formulas.", "SHA-256 Ed25519 evidence verification"),
    "docs/reference/case-reports/": ("Telegram Report Formats & Signed PDF Verification", "Configure Telegram evidence reports, filters, layouts and contents. Review report revisions, included assessments and verification of HTML and signed PDF.", "Telegram signed PDF report verification"),
    "docs/reference/account-export/": ("Telegram Account Export: Scope & Signed Archives", "Export the Telegram history an account can currently access. Review chat scope, resumable jobs, signed archives and minimized evidence sharing copies.", "Telegram account export"),
    "docs/reference/evidence/": ("Telegram Evidence Archive Format & Verification", "Inspect signed Telegram evidence ZIP contents: records, manifest, attachments and receipts. Verify file hashes and signatures with an independently trusted key.", "Telegram evidence archive format"),
    "docs/reference/witness/": ("Independent Evidence Witness & Journal Continuity", "Configure a TgWitness witness with its own key and Telegram bot. Verify journal continuity against signed checkpoints retained outside the collector.", "independent evidence witness"),
    "docs/reference/timestamp/": ("RFC 3161 Timestamps for Telegram Evidence", "Timestamp signed Telegram journal checkpoints with RFC 3161. Review what reaches the time authority and how to verify the returned timestamp response.", "RFC 3161 Telegram evidence timestamp"),
    "docs/reference/storage/": ("Telegram Evidence Backups, S3 & Object Lock", "Back up TgWitness evidence, move older media to object storage and retain locked copies. Review S3, rclone and recovery to a replacement machine.", "Telegram evidence backup S3 Object Lock"),
    "docs/reference/security/": ("TgWitness Security Model & Telegram Session Storage", "Review TgWitness authentication, session imports, encrypted secrets and network exposure. Understand threat boundaries and the vulnerability reporting process.", "TgWitness security model"),
    "docs/reference/architecture/": ("TgWitness Architecture: Collector, Journal & API", "Trace data through the TgWitness Telegram collector, signed journal, panel, workers and witness. Review the Python, FastAPI, Telethon and SQLite components.", "TgWitness architecture"),
    "docs/reference/verification/": ("TgWitness Test Evidence & Qualification Limits", "Read which TgWitness workflows were tested, on which revisions and environments. Separate synthetic checks, live Telegram results and unverified behavior.", "TgWitness verification test results"),
    "docs/reference/changelog/": ("TgWitness Changelog & Release Notes", "Read TgWitness changes by version, including unreleased work. Check release notes before assuming a source feature is included in an installed package.", "TgWitness changelog release notes"),
    "docs/reference/license/": ("TgWitness MIT License & Architectural Notice", "Read the TgWitness MIT license and the authors' architectural incompatibility statement. The project notice adds no condition to the software license.", "TgWitness MIT license"),
    "docs/reference/notice/": ("TgWitness Operator Notice & Source Record", "Read the TgWitness authors' operator incompatibility statement concerning Taylor Wessing, its scope and source record alongside the unchanged MIT license.", "TgWitness operator notice"),
}

RUSSIAN = {
    "": "Экспорт чатов Telegram и OSINT-расследования",
    "docs/": "Telegram: экспорт, расследования и проверка доказательств",
    "docs/reference/": "Справочник по сбору и проверке данных Telegram",
    "docs/start/": "Установка TgWitness для экспорта чатов Telegram",
    "docs/dedicated-account/": "Отдельный аккаунт для сбора данных Telegram",
    "docs/accounts/": "Подключение Telegram: QR, телефон и импорт сессий",
    "docs/proxies/": "Прокси Telegram: MTProxy, SOCKS5 и маршрутизация",
    "docs/exports/": "Экспорт чатов Telegram и проверка подписанного архива",
    "docs/capture/": "Экспорт Telegram через GitHub Actions",
    "docs/concepts/": "Доказательства Telegram: цепочка хешей и подписи",
    "docs/cases/": "OSINT-расследования по чатам Telegram",
    "docs/case-board/": "Доска дела: сообщения и доказательства Telegram",
    "docs/reports/": "Отчёты по Telegram: HTML и подписанный PDF",
    "docs/handover/": "Передача доказательств Telegram с ограничением данных",
    "docs/groups/": "Управление группами аккаунтов Telegram",
    "docs/archive/": "Поиск и анализ сохранённого архива Telegram",
    "docs/security/": "Защита сессий Telegram и хранилища доказательств",
    "docs/access/": "Доступ рецензентов к материалам дела Telegram",
    "docs/witness/": "Настройка бота-свидетеля для доказательств Telegram",
    "docs/server/": "Сервер TgWitness для сбора данных Telegram",
    "docs/troubleshooting/": "Telegram: ошибки входа, FloodWait и пропуски сбора",
    "docs/export-clinic/": "Экспорт Telegram Desktop: контролируемый эксперимент",
    "docs/validation/": "Скорость экспорта Telegram и проверенные результаты",
    "guides/modes.html": "Режимы сбора Telegram и уровни проверки доказательств",
    "docs/reference/overview/": "TgWitness: экспорт Telegram, OSINT и проверка данных",
    "docs/reference/quickstart/": "Установка TgWitness: Windows, Linux, macOS и Docker",
    "docs/reference/installation/": "Установка, проверка подписи и обновление TgWitness",
    "docs/reference/settings/": "Настройка сбора Telegram и параметров TgWitness",
    "docs/reference/accounts/": "Сессии Telegram: TData, Telethon и способы импорта",
    "docs/reference/access/": "Токены, области доступа и разрешения TgWitness",
    "docs/reference/connection/": "Прокси Telegram и безопасность подключения",
    "docs/reference/deployment/": "Развёртывание TgWitness: Docker, HTTPS и резервирование",
    "docs/reference/high-assurance/": "Phala и Intel TDX: аттестация сборщика Telegram",
    "docs/reference/panel/": "Панель TgWitness: чаты, журнал и экспорт Telegram",
    "docs/reference/collection/": "Сбор Telegram: сообщения, правки и уведомления об удалении",
    "docs/reference/secret-chats/": "Секретные чаты Telegram: состояние реализации",
    "docs/reference/history/": "Загрузка истории Telegram и подписанный отчёт о ходе",
    "docs/reference/operations/": "Эксплуатация TgWitness: сбор, экспорт и восстановление",
    "docs/reference/investigation/": "Режим расследования Telegram и область наблюдения",
    "docs/reference/features/": "Возможности TgWitness и ограничения сбора Telegram",
    "docs/reference/case-board/": "Аннотации Telegram со ссылками на исходные записи",
    "docs/reference/analysis/": "Анализ архива Telegram и ссылки на источники",
    "docs/reference/search/": "Полнотекстовый поиск по архиву Telegram",
    "docs/reference/mcp/": "MCP-сервер архива Telegram: доступ только для чтения",
    "docs/reference/cli/": "CLI для Telegram: поиск по архиву и экспорт JSONL",
    "docs/reference/media-analysis/": "OCR изображений и расшифровка аудио Telegram",
    "docs/reference/webhooks/": "Вебхуки TgWitness: HMAC-подпись и доставка событий",
    "docs/reference/showcase/": "Публикация сохранённых сообщений каналов Telegram",
    "docs/reference/how-it-works/": "Проверка доказательств: SHA-256 и Ed25519",
    "docs/reference/case-reports/": "Форматы отчётов Telegram и проверка подписанного PDF",
    "docs/reference/account-export/": "Экспорт аккаунта Telegram в подписанный архив",
    "docs/reference/evidence/": "Формат архива доказательств Telegram и проверка",
    "docs/reference/witness/": "Независимый свидетель и непрерывность журнала",
    "docs/reference/timestamp/": "Метки времени RFC 3161 для доказательств Telegram",
    "docs/reference/storage/": "Резервные копии Telegram: S3, Object Lock и восстановление",
    "docs/reference/security/": "Модель безопасности TgWitness и хранение сессий",
    "docs/reference/architecture/": "Архитектура TgWitness: сборщик, журнал и API",
    "docs/reference/verification/": "Проверки TgWitness: результаты и ограничения",
    "docs/reference/changelog/": "История изменений и примечания к выпускам TgWitness",
    "docs/reference/license/": "Лицензия MIT и архитектурное уведомление TgWitness",
    "docs/reference/notice/": "Уведомление авторов TgWitness и исходные материалы",
}


def clean(value, lang):
    if lang not in {"zh", "zh-Hans", "zh-Hant", "ja", "ko"}:
        value = re.sub(r"[\uff01-\uff5e]", lambda m: chr(ord(m[0]) - 0xFEE0), value)
        value = re.sub(r"(?<=[,;:])(?=[^\W\d_])", " ", value)
    return " ".join(value.split())


def local_path(path):
    first, separator, rest = path.partition("/")
    path = rest if separator and first in {*LANGUAGES, "am"} else path
    return path.removesuffix("index.html")


def metadata(path, title, description, lang):
    local = local_path(path)
    if local not in PAGES:
        raise ValueError("Missing page search intent: " + local)
    english_title, english_description, query = PAGES[local]
    if lang == "en":
        return english_title + " | TgWitness", english_description, query
    description = clean(description, lang)
    if lang == "ru":
        title = RUSSIAN[local]
    else:
        title = clean(title.removesuffix(" | TgWitness"), lang)
        if local.startswith("docs/reference/") and " · " in title:
            title = title.rsplit(" · ", 1)[0]
        topic = "Phala / Intel TDX" if local.endswith("high-assurance/") else "Telegram"
        if local not in {"docs/reference/license/", "docs/reference/notice/", "docs/reference/changelog/", "docs/reference/architecture/", "docs/reference/verification/", "docs/reference/installation/"} and topic.lower() not in title.lower():
            title = topic + " · " + title
    return title + " | TgWitness", description, title


def nodes(node):
    yield node
    for child in node.children:
        yield from nodes(child)


def enrich(source, path):
    tree = _Tree(source)
    root = next(n for n in nodes(tree.root) if n.tag == "html")
    head = next(n for n in root.children if n.tag == "head")
    elements = list(nodes(head))
    title = next(n for n in elements if n.tag == "title")
    description = next(n for n in elements if n.tag == "meta" and n.attrs.get("name") == "description")
    script = next(n for n in elements if n.tag == "script" and n.attrs.get("type") == "application/ld+json")
    data = json.loads(source[script.open_end:script.close_start])
    page = next(n for n in data["@graph"] if n["@type"] == "WebPage")
    lang = page.get("inLanguage", root.attrs.get("lang", "en"))
    old_title = html.unescape(source[title.open_end:title.close_start])
    new_title, summary, query = metadata(path, old_title, description.attrs["content"], lang)
    edits = [(title.open_end, title.close_start, html.escape(new_title))]
    wanted = {"description": summary, "og:title": new_title, "og:description": summary,
              "twitter:title": new_title, "twitter:description": summary}
    present = set()
    for node in elements:
        if node.tag != "meta":
            continue
        key = node.attrs.get("name", node.attrs.get("property"))
        if key in wanted:
            present.add(key)
            attrs = {**node.attrs, "content": wanted[key]}
            tag = '<meta ' + ' '.join(f'{k}="{html.escape(v, quote=True)}"' for k, v in attrs.items()) + '>'
            edits.append((node.open_start, node.open_end, tag))
    missing = ''.join(f'<meta name="{key}" content="{html.escape(wanted[key], quote=True)}">' for key in ("twitter:title", "twitter:description") if key not in present)
    edits.append((head.close_start, head.close_start, missing))
    page.update(name=new_title, description=summary, keywords=[query])
    for node in data["@graph"]:
        if node["@type"] == "SoftwareSourceCode":
            node["description"] = PAGES[""][1]
    encoded = json.dumps(data, ensure_ascii=False).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    edits.append((script.open_end, script.close_start, encoded))
    local = local_path(path)
    if local.startswith("docs/") and local not in {"docs/dedicated-account/", "docs/export-clinic/", "docs/validation/", "docs/reference/license/", "docs/reference/notice/"}:
        heading = next(n for n in nodes(root) if n.tag == "h1")
        edits.append((heading.open_end, heading.close_start, html.escape(new_title.removesuffix(" | TgWitness"))))
    footer = [n for n in nodes(root) if n.tag == "footer"][-1]
    link_container = next((n for n in reversed(list(nodes(footer))) if n.tag == "nav"), footer)
    folder = posixpath.dirname(path)
    present_links = {n.attrs.get("href") for n in nodes(footer) if n.tag == "a"}
    links = ' '.join(f'<a href="{posixpath.relpath(name, folder or ".")}">{name}</a>' for name in ("llms.txt", "llms-full.txt", "sitemap.xml") if posixpath.relpath(name, folder or ".") not in present_links)
    if links:
        edits.append((link_container.close_start, link_container.close_start, ' ' + links))
    for start, end, value in sorted(edits, reverse=True):
        source = source[:start] + value + source[end:]
    return source
