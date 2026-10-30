"""Download public official reference pages for a dated, local engineering review."""
import hashlib
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

URLS = {
    "authorization": "https://core.telegram.org/api/auth",
    "api_id": "https://core.telegram.org/api/obtaining_api_id",
    "signing_in": "https://docs.telethon.dev/en/stable/basic/signing-in.html",
    "transports": "https://core.telegram.org/mtproto/mtproto-transports",
    "desktop_storage": "https://raw.githubusercontent.com/telegramdesktop/tdesktop/dev/Telegram/SourceFiles/storage/storage_account.cpp",
    "updates": "https://core.telegram.org/api/updates",
    "reactions": "https://core.telegram.org/api/reactions",
    "admin_log": "https://core.telegram.org/api/recent-actions",
    "reaction_actors": "https://core.telegram.org/method/messages.getMessageReactionsList",
    "delete_update": "https://core.telegram.org/constructor/updateDeleteMessages",
    "channel_delete": "https://core.telegram.org/constructor/updateDeleteChannelMessages",
    "reaction_update": "https://core.telegram.org/constructor/updateMessageReactions",
    "admin_log_method": "https://core.telegram.org/method/channels.getAdminLog",
    "admin_deleted_message": "https://core.telegram.org/constructor/channelAdminLogEventActionDeleteMessage",
    "api_terms": "https://core.telegram.org/api/terms",
    "telethon_sessions": "https://docs.telethon.dev/en/stable/concepts/sessions.html",
    "telethon_updates": "https://docs.telethon.dev/en/stable/concepts/updates.html",
    "telethon_events": "https://docs.telethon.dev/en/stable/modules/events.html",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="+", choices=URLS)
    args = parser.parse_args()
    output = Path(__file__).resolve().parents[1] / "test-results" / "research"
    output.mkdir(parents=True, exist_ok=True)

    def fetch(item):
        name, url = item
        try:
            response = requests.get(url, timeout=(10, 35))
            response.raise_for_status()
            parsed = BeautifulSoup(response.text, "html.parser")
            content = parsed.select_one("#dev_page_content") or parsed.select_one('[role="main"]') or parsed
            for element in content.select("script,style"):
                element.decompose()
            text = content.get_text("\n", strip=True)
            (output / (name + ".txt")).write_text(text, encoding="utf-8")
            return {"name": name, "url": url, "retrieved_at": datetime.now(timezone.utc).isoformat(),
                    "status": response.status_code, "sha256": hashlib.sha256(response.content).hexdigest(),
                    "characters": len(text)}
        except Exception as exc:
            return {"name": name, "url": url, "error": type(exc).__name__}

    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(fetch, ((k, URLS[k]) for k in args.only) if args.only else URLS.items()))
    (output / ("connection-sources.json" if args.only else "sources.json")).write_text(json.dumps(receipts, indent=2), encoding="utf-8")
    print(json.dumps(receipts, indent=2))


if __name__ == "__main__":
    main()
