from contextlib import contextmanager
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread

if __package__:
    from .site_export_clinic import DOWNLOADS
    from .site_test_server import SiteHandler
else:
    from site_export_clinic import DOWNLOADS
    from site_test_server import SiteHandler


class MediaHandler(SiteHandler):
    def public_path(self):
        path = super().public_path()
        if path is None or path.parent != self.root or path.name not in {*DOWNLOADS, "download-manifest.json", "SHA256SUMS.txt"}:
            return None
        return path

    def end_headers(self):
        path = getattr(self, "_public_path", None)
        if path is not None and path.suffix in {".zip", ".mkv"}:
            self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        super().end_headers()


@contextmanager
def media_server(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Media directory must exist")
    prefix = "/export-clinic-media/"
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(MediaHandler, root=root, prefix=prefix))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}{prefix}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
