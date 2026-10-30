"""Compare the running program with one commit of a public GitHub repository, such as an operator's fork.

Every measured program file (the set in provenance.source_files) is compared by its git blob id with
the file in the commit's tree, so no token and no download of the repository are needed. A checkout
with Windows line endings is compared as git stored it (text=auto in .gitattributes).
"""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import quote

from . import netclient
from .provenance import source_files, source_tree_sha256
from .store import utcnow

API = "https://api.github.com/repos/"
PACKAGE = Path(__file__).parent
REPOSITORY = re.compile(r"(?:(?:https?://)?(?:www\.)?github\.com/)?([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?")
REF = re.compile(r"[\w.+/-]{1,200}")
LISTED = 50  # file names kept per category in the result


class NotFound(ValueError):
    pass


class Limited(ValueError):
    pass


def repository(text):
    """(owner, name) of github.com/owner/name, a full https address or owner/name."""
    found = REPOSITORY.fullmatch((text or "").strip())
    if not found:
        raise ValueError("not a GitHub repository")
    return found.group(1), found.group(2)


def blob_ids(data):
    """Git blob ids of a file as it is on disk and, for a CRLF checkout, as git stored it."""
    def blob(content):
        return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()
    ids = {blob(data)}
    if b"\r\n" in data and b"\0" not in data:
        ids.add(blob(data.replace(b"\r\n", b"\n")))
    return ids


async def github(path, network):
    try:
        _status, _headers, body = await netclient.request(
            "GET", API + path, network, timeout=30, limit=32 * 1024 * 1024,
            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    except netclient.HTTPError as error:
        if error.status in (404, 422):
            raise NotFound(path) from error
        if error.status in (403, 429):
            raise Limited(path) from error
        raise
    return json.loads(body)


def compare(local, remote):
    changed = sorted(p for p in local.keys() & remote.keys() if remote[p] not in local[p])
    extra = sorted(local.keys() - remote.keys())  # here, not in the commit
    missing = sorted(remote.keys() - local.keys())  # in the commit, not here
    return {"matches": not (changed or extra or missing), "changed": changed[:LISTED],
            "extra": extra[:LISTED], "missing": missing[:LISTED],
            "differences": len(changed) + len(extra) + len(missing)}


async def check(text, ref, network, root=PACKAGE):
    owner, name = repository(text)
    if not REF.fullmatch(ref or ""):
        raise NotFound(ref)
    base = quote(owner) + "/" + quote(name)
    commit = (await github(base + "/commits/" + quote(ref, safe=""), network))["sha"]
    tree = await github(base + "/git/trees/" + commit + "?recursive=1", network)
    if tree.get("truncated"):
        raise Limited("tree truncated")
    measured = source_files(root)
    prefix = root.name + "/"
    remote = {}
    for entry in tree["tree"]:
        path = entry["path"]
        if entry["type"] == "blob" and path.startswith(prefix):
            relative = path[len(prefix):]
            if Path(relative).suffix in (".py", ".js", ".css", ".html", ".svg") and "__pycache__" not in relative:
                remote[relative] = entry["sha"]
    local = {relative: blob_ids((Path(root) / relative).read_bytes()) for relative in measured}
    return {"repository": "https://github.com/" + owner + "/" + name, "ref": ref, "commit": commit,
            "checked_at": utcnow(), "files": len(local), "source_tree_sha256": source_tree_sha256(measured),
            **compare(local, remote)}
