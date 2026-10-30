"""Read-only public monitor for several account workspaces; owns no Telegram user session."""
import argparse
import asyncio
import copy
import json
import re
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
import uvicorn

from .store import canonical, utcnow
from .verify import parse_time
from .witness import Witness, http_address, proxy_config

STATIC = Path(__file__).with_name("static")


def load_config(path):
    path = Path(path).resolve()
    data = json.loads(path.read_text(encoding="utf-8"))
    allowed = {"title", "data_dir", "interval", "timeout", "workspaces"}
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError("Unknown proof configuration fields")
    title = data.get("title", "TgWitness · live proof")
    if not isinstance(title, str) or not 1 <= len(title) <= 100:
        raise ValueError("Proof title must contain 1-100 characters")
    interval, timeout = data.get("interval", 5), data.get("timeout", 20)
    if type(interval) is not int or not 1 <= interval <= 1440:
        raise ValueError("Proof interval must be 1-1440 minutes")
    if type(timeout) is not int or not 5 <= timeout <= 600:
        raise ValueError("Proof timeout must be 5-600 seconds")
    rows = data.get("workspaces")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        raise ValueError("Configure 1-32 workspaces")
    root = (path.parent / data.get("data_dir", "proof-data")).resolve()
    result, aliases, keys = [], set(), set()

    def secret(row, field):
        filename = row.get(field)
        if not isinstance(filename, str) or not filename:
            raise ValueError("Missing " + field + " for " + row["id"])
        value = (path.parent / filename).read_text(encoding="utf-8").strip()
        if not value or len(value) > 256:
            raise ValueError("Invalid secret file for " + row["id"])
        return value

    for row in rows:
        fields = {"id", "label", "collector", "collector_fingerprint", "token_file", "bot_token_file", "channel", "proxy", "bot_api"}
        if not isinstance(row, dict) or set(row) - fields:
            raise ValueError("Unknown workspace configuration fields")
        alias = row.get("id", "")
        if not isinstance(alias, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", alias) or alias in aliases:
            raise ValueError("Workspace IDs must be unique simple aliases")
        aliases.add(alias)
        label = row.get("label", alias)
        if not isinstance(label, str) or not 1 <= len(label) <= 80:
            raise ValueError("Workspace labels must contain 1-80 characters")
        pin = row.get("collector_fingerprint", "")
        if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin) or pin in keys:
            raise ValueError("Pin a distinct collector fingerprint for each workspace")
        keys.add(pin)
        address = row.get("collector", "")
        parts = urlsplit(address)
        if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password
                or parts.query or parts.fragment):
            raise ValueError("Collector must be an HTTP(S) address without credentials, query or fragment")
        channel = row.get("channel")
        if channel is not None and (not isinstance(channel, str) or not re.fullmatch(r"@[A-Za-z0-9_]{5,32}|-?\d{1,20}", channel)):
            raise ValueError("Use a Telegram @channel or numeric chat ID")
        if bool(channel) != bool(row.get("bot_token_file")):
            raise ValueError("Broadcasting requires both channel and bot_token_file")
        bot_api = http_address(row.get("bot_api", "https://api.telegram.org"))
        network = proxy_config(row.get("proxy"))
        result.append({"id": alias, "label": label, "root": root / alias, "collector": address,
                       "pinned": pin, "token": secret(row, "token_file"), "channel": channel,
                       "bot_token": secret(row, "bot_token_file") if channel else None,
                       "interval": interval, "timeout": timeout, "bot_api": bot_api, "network": network})
    return {"title": title, "interval": interval, "workspaces": result}


class ProofWatcher(Witness):
    def __init__(self, config):
        self.alias, self.label = config["id"], config["label"]
        super().__init__(**{k: v for k, v in config.items() if k not in ("id", "label")}, title=self.label)
        recent = self.store.events_of(("witness.anchor", "witness.no_response"), limit=1)
        self.latest = self.receipt(recent[0]) if recent else None

    def receipt(self, event):
        payload = event["payload"]
        status = payload.get("status", "no_response")
        if status == "ok" and not payload.get("capture"):
            status = "legacy_head"
        broadcast = {"status": "disabled"}
        if self.send:
            recent = self.store.events_of(("witness.posted", "witness.post_failed"), limit=1)
            if recent and recent[0]["payload"].get("record") == event["seq"]:
                broadcast = {"status": "posted" if recent[0]["kind"] == "witness.posted" else "failed"}
                if broadcast["status"] == "posted":
                    broadcast["message_id"] = recent[0]["payload"]["message_id"]
            else:
                broadcast = {"status": "unknown"}
        statement = {"format": "tgwitness-public-proof-v1", "alias": self.alias,
                     "witness_public_key": self.key.public_key, "observed_at": event["observed_at"],
                     "witness_seq": event["seq"], "witness_record_hash": event["hash"], "status": status,
                     "collector_fingerprint": self.pinned, "interval_minutes": self.interval,
                     "checkpoint": payload.get("checkpoint"), "capture": payload.get("capture"),
                     "capture_delta": payload.get("capture_delta"), "broadcast": broadcast}
        return {"statement": statement, "signature": self.key.sign(canonical(statement))}

    async def tick(self):
        event = await super().tick()
        self.latest = self.receipt(event)
        return event


def create_app(config, watcher_factory=ProofWatcher):
    watchers, tasks = [], []

    @asynccontextmanager
    async def lifespan(app):
        try:
            for row in config["workspaces"]:
                watchers.append(watcher_factory(row))
            tasks.extend(asyncio.create_task(w.run()) for w in watchers)
            yield
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for watcher in watchers:
                watcher.close()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.watchers, app.state.tasks = watchers, tasks

    @app.middleware("http")
    async def headers(request, call_next):
        if request.method not in ("GET", "HEAD"):
            return JSONResponse({"detail": "Read-only monitor"}, status_code=405)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        return response

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "proof.html")

    @app.get("/proof.css")
    async def style():
        return FileResponse(STATIC / "proof.css")

    @app.get("/proof.js")
    async def script():
        return FileResponse(STATIC / "proof.js")

    @app.get("/mark.svg")
    async def mark():
        return FileResponse(STATIC / "mark.svg")

    @app.get("/healthz")
    async def health():
        healthy = bool(tasks) and all(not t.done() for t in tasks)
        return JSONResponse({"monitor_running": healthy}, status_code=200 if healthy else 503)

    @app.get("/api/proof")
    async def status():
        now = utcnow()
        rows = []
        for watcher, task in zip(watchers, tasks):
            proof = copy.deepcopy(watcher.latest)
            stale = not proof or (parse_time(now) - parse_time(proof["statement"]["observed_at"])).total_seconds() > watcher.interval * 150
            rows.append({"id": watcher.alias, "label": watcher.label, "stale": stale,
                         "monitor_running": not task.done(), "witness_fingerprint": watcher.fingerprint,
                         "collector_fingerprint": watcher.pinned, "proof": proof})
        return {"title": config["title"], "generated_at": now, "interval_minutes": config["interval"], "workspaces": rows}

    @app.get("/api/proof/{alias}")
    async def download(alias: str):
        watcher = next((w for w in watchers if w.alias == alias), None)
        if watcher is None or not watcher.latest:
            raise HTTPException(404, "No proof available")
        return JSONResponse(watcher.latest, headers={"Content-Disposition": f'attachment; filename="proof-{alias}.json"'})

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
    except (ValueError, OSError, TypeError) as exc:
        parser.exit(1, "Proof configuration: " + str(exc) + "\n")
    if args.check_config:
        print("Proof configuration valid:", len(config["workspaces"]), "distinct pinned workspaces; no connection opened.")
        return
    uvicorn.run(create_app(config), host=args.host, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
