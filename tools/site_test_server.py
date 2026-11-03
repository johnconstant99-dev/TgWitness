from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
import re
from threading import Thread
from urllib.parse import unquote, urlsplit


class SiteHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, root: Path, prefix: str, html_replacements=None, **kwargs):
        self.root = root
        self.prefix = prefix
        self.html_replacements = html_replacements or {}
        super().__init__(*args, directory=str(root), **kwargs)

    def log_message(self, *args):
        pass

    def copyfile(self, source, outputfile):
        try:
            if self.remaining is None:
                super().copyfile(source, outputfile)
            else:
                while self.remaining:
                    block = source.read(min(65536, self.remaining))
                    if not block:
                        break
                    outputfile.write(block)
                    self.remaining -= len(block)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
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
            if any(part in {".", ".."} or ":" in part or part.rstrip(" .") != part
                   or re.fullmatch(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?", part, re.I)
                   for part in parts):
                return None
            resolved = self.root.joinpath(*parts).resolve()
            return resolved if resolved.is_relative_to(self.root) else None
        except (UnicodeError, ValueError, OSError, RuntimeError):
            return None

    def send_head(self):
        self.remaining = None
        self._public_path = self.public_path()
        if self._public_path is None:
            self.send_error(404)
            return None
        content_path = self._public_path
        if self._public_path.is_dir():
            for name in ("index.html", "index.htm"):
                index = self._public_path / name
                if index.exists():
                    if not index.resolve().is_relative_to(self.root):
                        self.send_error(404)
                        return None
                    content_path = index
                    break
        if self.html_replacements and content_path.is_file() and content_path.suffix == ".html":
            data = content_path.read_bytes()
            for old, new in self.html_replacements.items():
                data = data.replace(old.encode("utf-8"), new.encode("utf-8"))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return BytesIO(data)
        request_range = self.headers.get("Range")
        if request_range and self._public_path.is_file():
            match = re.fullmatch(r"bytes=(\d*)-(\d*)", request_range.strip())
            size = self._public_path.stat().st_size
            if not match or not any(match.groups()):
                self.send_error(416)
                return None
            first, last = match.groups()
            start = int(first) if first else max(0, size - int(last))
            end = min(int(last), size - 1) if first and last else size - 1
            if start >= size or end < start:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{size}")
                self.end_headers()
                return None
            handle = self._public_path.open("rb")
            handle.seek(start)
            self.remaining = end - start + 1
            self.send_response(206)
            self.send_header("Content-Type", self.guess_type(str(self._public_path)))
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_header("Content-Length", str(self.remaining))
            self.send_header("Last-Modified", self.date_time_string(self._public_path.stat().st_mtime))
            self.end_headers()
            return handle
        return super().send_head()

    def end_headers(self):
        self.send_header("Accept-Ranges", "bytes")
        super().end_headers()

    def translate_path(self, path):
        return str(self._public_path)

    def list_directory(self, path):
        self.send_error(404)
        return None


@contextmanager
def site_server(root: Path, prefix: str = "/TgWitness/", *, html_replacements=None):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Site root must be a directory")
    if not re.fullmatch(r"/[A-Za-z0-9_-]+/", prefix):
        raise ValueError("Site prefix must be one absolute path component")
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(SiteHandler, root=root, prefix=prefix, html_replacements=html_replacements))
    thread = Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}{prefix}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
