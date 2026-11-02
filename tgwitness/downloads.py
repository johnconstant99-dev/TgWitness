"""Own temporary downloads across worker cancellation and broken HTTP connections."""
from pathlib import Path

from starlette.responses import FileResponse

from .workers import complete_in_thread


async def build_file(function):
    path = None

    def build():
        nonlocal path
        path = function()
        return path

    try:
        return await complete_in_thread(build)
    except BaseException:
        if path is not None:
            Path(path).unlink(missing_ok=True)
        raise


class TemporaryDownload(FileResponse):
    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            Path(self.path).unlink(missing_ok=True)


class RetainedDownload(FileResponse):
    """Release a job lease even if streaming fails or the client disconnects."""
    def __init__(self, path, *, release, **kwargs):
        super().__init__(path, **kwargs)
        self.release = release

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.release()
