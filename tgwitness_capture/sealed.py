"""Official-client recorder entry point for the pinned GitHub-hosted supervisor."""
import argparse
import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import re
import time

from .export import export_zip
from .journal import durable_write
from .service import Config, create_app


def create_sealed_app(root, output, session):
    root, output = Path(root), Path(output)
    if (session.get("client") != "official_web" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", session.get("token", ""))
            or type(session.get("seconds")) is not int or not 60 <= session["seconds"] <= 7200):
        raise ValueError("Invalid official-client session")
    for path in (root, output):
        if path.exists() and any(path.iterdir()):
            raise ValueError("A sealed official-client session requires empty data and output directories")
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    durable_write(root / "control-token.txt", session["token"].encode(), exclusive=True)
    config = Config(
        kind="browser", operator="recipient", public_origin=session["public_origin"],
        route_label="Isolated browser network through one required upstream; periodic IP checks",
        official={"proxy_server": "http://official-gateway:3128", "expected_ip": session.get("expected_ip", ""),
                  "session_minutes": session["seconds"] // 60, "require_video": True},
        video_input_args=["-f", "x11grab", "-framerate", "12", "-video_size", "1280x720", "-i", ":99.0"])
    app = create_app(root, config)
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app):
        async with original_lifespan(app):
            recorder = app.state.recorder
            recorder.journal.append("official.sealed_started", {"context": session["context"],
                                    "client": "official_web", "session_import_allowed": False,
                                    "upstream": session["upstream_public"], "network": "isolated-required-proxy",
                                    "authority": "verify the external GitHub attestation and approved workflow"})
            deadline = time.monotonic() + session["seconds"]

            async def supervise():
                while True:
                    if time.monotonic() >= deadline or recorder.official.phase == "finished":
                        recorder.official.stop_requested = True
                        async with recorder.lock:
                            recorder.settings["enabled"] = False
                            await asyncio.to_thread(recorder.video.stop)
                            if recorder.official.phase != "finished":
                                await recorder.official.pause("SessionDeadline")
                                await recorder.official.finish()
                            if not any(e["kind"] == "official.opened" for e in recorder.journal.events()):
                                durable_write(output / "result.json", b'{"phase":"cancelled"}', exclusive=True)
                                return
                            recorder.journal.append("official.sealed_finished", {
                                "context": session["context"], "deadline_reached": time.monotonic() >= deadline,
                                "logout_confirmed": recorder.official.logout_confirmed,
                                "profile_context_closed": recorder.official.page is None,
                                "scope": "observed rendered material; not a full-account export"})
                            await asyncio.to_thread(export_zip, recorder.journal, output / "evidence.zip")
                            durable_write(output / "result.json", b'{"phase":"sealed"}', exclusive=True)
                        return
                    await asyncio.sleep(.5)

            async def guarded_supervise():
                try:
                    await supervise()
                except Exception:
                    recorder.settings["enabled"] = False
                    recorder.official.stop_requested = True
                    recorder.video.abort()
                    await recorder.official.close()
                    # Do not disclose rendered content or credentials through supervisor errors.
                    durable_write(output / "result.json", b'{"phase":"failed"}', exclusive=True)

            task = asyncio.create_task(guarded_supervise())
            try:
                yield
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    app.router.lifespan_context = lifespan
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--data", type=Path, default=Path("/data"))
    parser.add_argument("--out", type=Path, default=Path("/output"))
    args = parser.parse_args()
    import uvicorn
    session = json.loads(args.config.read_bytes())
    uvicorn.run(create_sealed_app(args.data, args.out, session), host="0.0.0.0", port=8787,
                access_log=False, workers=1, proxy_headers=False)


if __name__ == "__main__":
    main()
