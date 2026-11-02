"""Serve the panel with integrity metadata for its local scripts and styles."""
import base64
import hashlib
import html
import json
from pathlib import Path
import re
from urllib.parse import urljoin, urlsplit

from starlette.responses import HTMLResponse
from starlette.staticfiles import StaticFiles


POLICY = ("default-src 'self'; script-src 'self'{script_hash}; style-src 'self'; "
          "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; "
          "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
REFERENCE = re.compile(r'''["']([^"'\s<>]+\.js(?:\?[^"'\s<>]*)?)["']''')
TAG = re.compile(r'<(?:script|link)\b[^>]*>', re.I)
URL = re.compile(r'''\b(?:src|href)=["']([^"']+)["']''', re.I)


def integrity(data):
    return 'sha384-' + base64.b64encode(hashlib.sha384(data).digest()).decode('ascii')


class PanelFiles(StaticFiles):
    def __init__(self, directory):
        super().__init__(directory=directory, html=True)
        root = Path(directory)
        files = {"/" + file.relative_to(root).as_posix(): file.read_bytes()
                 for file in root.rglob('*') if file.is_file() and file.suffix in ('.js', '.css')}
        hashes = {path: integrity(data) for path, data in files.items()}
        document = (root / 'index.html').read_text(encoding='utf-8')
        modules = {path: value for path, value in hashes.items() if path.endswith('.js')}
        # Include versioned import URLs as well as unversioned module URLs. The
        # map is metadata only: it does not eagerly load otherwise lazy views.
        for path, source in [('/index.html', document), *((p, d.decode('utf-8')) for p, d in files.items() if p.endswith('.js'))]:
            for reference in REFERENCE.findall(source):
                resolved = urljoin(path, reference)
                parts = urlsplit(resolved)
                if not parts.netloc and not parts.scheme and parts.path in hashes:
                    modules[resolved] = hashes[parts.path]
        metadata = json.dumps({'integrity': modules}, separators=(',', ':'), sort_keys=True).replace('<', '\\u003c')
        metadata_hash = integrity(metadata.encode())

        def decorate(match):
            tag = match.group()
            reference = URL.search(tag)
            if not reference:
                return tag
            path = urlsplit(html.unescape(reference[1])).path
            if path not in hashes:
                return tag
            return tag[:-1] + ' integrity="' + hashes[path] + '" crossorigin="anonymous">'

        self.document = TAG.sub(decorate, document).replace('<script', '<script type="importmap">' + metadata + '</script><script', 1)
        self.policy = POLICY.format(script_hash=" '" + metadata_hash + "'")

    async def get_response(self, path, scope):
        if path in ('.', '', 'index.html') and scope['method'] in ('GET', 'HEAD'):
            response = HTMLResponse(self.document, headers={'Content-Security-Policy': self.policy, 'Cache-Control': 'no-store'})
            if scope['method'] == 'HEAD':
                response.body = b''
            return response
        return await super().get_response(path, scope)
