"""Stream an authenticated export to disk without buffering it in the browser."""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


def download_export(url, token, destination, fmt="zip", profile="default", max_bytes=5 * 1024**3):
    parsed = urlsplit(url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Use a server origin without credentials, query parameters or a path.")
    if parsed.scheme == "http":
        try:
            local = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            local = parsed.hostname == "localhost"
        if not local:
            raise ValueError("Use HTTPS for remote servers, or a local SSH tunnel.")
    if fmt not in ("zip", "jsonl", "csv", "html") or (profile != "default" and not re.fullmatch(r"[a-f0-9]{32}", profile)):
        raise ValueError("Invalid format or profile identifier.")
    if not token or any(not 32 < ord(c) < 127 for c in token) or max_bytes <= 0:
        raise ValueError("Invalid access token or size limit.")
    destination = Path(destination)
    if destination.exists():
        raise ValueError("Output exists; choose a new destination.")
    factory = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = factory(parsed.hostname, parsed.port, timeout=600)
    temp = None
    try:
        prefix = "" if profile == "default" else "/profiles/" + profile
        connection.request("GET", prefix + "/api/export/" + fmt,
                           headers={"Authorization": "Bearer " + token, "Accept-Encoding": "identity"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Export request failed with HTTP " + str(response.status) + "; redirects are not followed.")
        declared = response.getheader("Content-Length")
        expected = int(declared) if declared and declared.isdecimal() else None
        if expected is not None and expected > max_bytes:
            raise ValueError("Export exceeds the configured download limit.")
        total, digest = 0, hashlib.sha256()
        with tempfile.NamedTemporaryFile(prefix=".tgwitness-download-", suffix=".part",
                                         dir=destination.parent, delete=False) as output:
            temp = Path(output.name)
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("Export exceeds the configured download limit.")
                output.write(chunk)
                digest.update(chunk)
            if expected is not None and total != expected:
                raise ValueError("Incomplete export response.")
            output.flush()
            os.fsync(output.fileno())


        try:
            os.link(temp, destination)
        except FileExistsError:
            raise ValueError("Output was created by another process; it was not overwritten.") from None
        except OSError:
            created = False
            try:
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                created = True
                with os.fdopen(fd, "wb") as output, temp.open("rb") as incoming:
                    while chunk := incoming.read(1024 * 1024):
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            except BaseException:
                if created:
                    destination.unlink(missing_ok=True)
                raise
        return {"file": str(destination), "bytes": total, "sha256": digest.hexdigest(),
                "profile": profile, "note": "Transfer checksum only. Verify the signed ZIP separately."}
    finally:
        connection.close()
        if temp:
            temp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8787")
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--format", choices=("zip", "jsonl", "csv", "html"), default="zip")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--max-mib", type=int, default=5120)
    args = parser.parse_args()
    try:
        if args.token_file.stat().st_size > 4096:
            raise ValueError("Invalid token file.")
        token = args.token_file.read_text().strip()
        result = download_export(args.url, token, args.out, args.format, args.profile, args.max_mib * 1024**2)
        print(json.dumps(result, indent=2))
    except UnicodeError:
        parser.exit(1, "Download failed: token file must contain a plain ASCII access token.\n")
    except (ValueError, OSError, http.client.HTTPException) as exc:
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        parser.exit(1, "Download failed: " + message + "\n")


if __name__ == "__main__":
    main()
