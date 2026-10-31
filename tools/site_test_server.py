"""Serve the built site under its Pages prefix without copying the artifact."""

from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
from threading import Thread
from urllib.parse import unquote, urlsplit


class SiteHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, root: Path, prefix: str, **kwargs):
        self.root = root
        self.prefix = prefix
        super().__init__(*args, directory=str(root), **kwargs)

    def log_message(self, *args):
        pass

    def copyfile(self, source, outputfile):
        try:
            super().copyfile(source, outputfile)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # Navigation can cancel an asset response before the browser reads it.
            pass

    def public_path(self) -> Path | None:
        try:
            request = urlsplit(self.path)
            if request.scheme or request.netloc or re.search(r"%(?![0-9a-fA-F]{2})", request.path):
                return None
            path = unquote(request.path, errors="strict")
            if "\\" in path or any(ord(char) < 32 for char in path):
                return None
            if path == self.prefix.rstrip("/"):
                relative = ""
            elif path.startswith(self.prefix):
                relative = path[len(self.prefix):]
            else:
                return None
            parts = [part for part in relative.split("/") if part]
            # Reject traversal and Windows path aliases before filesystem resolution.
            if any(part in {".", ".."} or ":" in part or part.rstrip(" .") != part
                   or re.fullmatch(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?", part, re.I)
                   for part in parts):
                return None
            resolved = self.root.joinpath(*parts).resolve()
            return resolved if resolved.is_relative_to(self.root) else None
        except (UnicodeError, ValueError, OSError, RuntimeError):
            return None

    def send_head(self):
        self._public_path = self.public_path()
        if self._public_path is None:
            self.send_error(404)
            return None
        if self._public_path.is_dir():
            for name in ("index.html", "index.htm"):
                index = self._public_path / name
                if index.exists():
                    if not index.resolve().is_relative_to(self.root):
                        self.send_error(404)
                        return None
                    break
        return super().send_head()

    def translate_path(self, path):
        # send_head validates once; a second URL decode could change the target.
        return str(self._public_path)

    def list_directory(self, path):
        self.send_error(404)
        return None


@contextmanager
def site_server(root: Path, prefix: str = "/TgWitness/"):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Site root must be a directory")
    if not re.fullmatch(r"/[A-Za-z0-9_-]+/", prefix):
        raise ValueError("Site prefix must be one absolute path component")
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(SiteHandler, root=root, prefix=prefix))
    thread = Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}{prefix}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
