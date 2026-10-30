"""Offline read-only conversion of a trusted Telethon SQLite session to StringSession."""
import argparse
import ipaddress
import os
import sqlite3
from pathlib import Path

from telethon.crypto import AuthKey
from telethon.sessions import StringSession


def convert_telethon(source):
    source = Path(source).resolve(strict=True)
    if not source.is_file() or source.stat().st_size > 64 * 1024**2:
        raise ValueError("Expected a closed Telethon SQLite session file, at most 64 MiB.")
    if any(Path(str(source) + suffix).exists() for suffix in ("-wal", "-journal")):
        raise ValueError("Close the original client and create a consistent offline session copy first.")
    with source.open("rb") as stream:
        if stream.read(16) != b"SQLite format 3\0":
            raise ValueError("Not a Telethon SQLite session. tdata, JSON and Pyrogram sessions are not accepted.")
    db = sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4096)
        objects = dict(db.execute("SELECT name,type FROM sqlite_master WHERE name IN ('version','sessions')"))
        if objects != {"version": "table", "sessions": "table"}:
            raise ValueError("Expected actual Telethon version and sessions tables.")
        versions = db.execute("SELECT version FROM version LIMIT 2").fetchall()
        if versions not in ([(7,)], [(8,)]):
            raise ValueError("Only reviewed Telethon SQLite schema versions 7 and 8 are supported.")
        rows = db.execute("SELECT dc_id,server_address,port,auth_key FROM sessions LIMIT 2").fetchall()
        if len(rows) != 1:
            raise ValueError("Expected one authorized Telegram session.")
        dc, address, port, key = rows[0]
        if not (type(dc) is int and 1 <= dc <= 255 and type(port) is int and 1 <= port <= 65535
                and isinstance(key, bytes) and len(key) == 256):
            raise ValueError("Invalid or unauthorized Telethon session.")
        ipaddress.ip_address(address)
        result = StringSession()
        result.set_dc(dc, address, port)
        result.auth_key = AuthKey(key)
        return result.save()
    except (sqlite3.Error, TypeError):
        raise ValueError("Invalid or unsupported Telethon session schema.") from None
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = convert_telethon(args.source)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as output:
            output.write(value)
        print("Converted locally. Load the output file in Connection. It grants account access; protect it.")
        print("No Telegram request was made. API ID/hash are still required. Close the other client before using this authorization.")
    except (ValueError, OSError):
        parser.exit(1, "Conversion failed. Check the supported schema, closed source, and unused output path. No secret was printed.\n")


if __name__ == "__main__":
    main()
