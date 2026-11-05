"""Telegram SHA-256 range manifests, collected without file payload downloads.

File IDs and access hashes are not content hashes. A manifest identifies the
exact document or photo size; its last range can extend beyond EOF, as Telegram
hashes the bytes that actually exist. No access hash/file reference is exported.
"""
import argparse
import hashlib
import json
from pathlib import Path

from telethon import errors
from telethon.tl import functions as f, types as t

FORMAT = "telegram-file-hashes-v1"
MAX_RANGES = 65536


def representation(media):
    item = getattr(media, "document", None) or getattr(media, "photo", None) or media
    if isinstance(item, t.Document):
        return {"kind": "document", "id": item.id, "dc_id": item.dc_id,
                "variant": "original", "bytes": item.size}
    if isinstance(item, t.Photo):
        sizes = [(max(getattr(s, "sizes", None) or [getattr(s, "size", 0)]), s)
                 for s in item.sizes if isinstance(s, (t.PhotoSize, t.PhotoSizeProgressive))]
        if sizes:
            size, thumb = max(sizes, key=lambda pair: pair[0])
            return {"kind": "photo", "id": item.id, "dc_id": item.dc_id,
                    "variant": thumb.type, "bytes": size, "width": thumb.w, "height": thumb.h}
    return None


def location(media, info):
    item = getattr(media, "document", None) or getattr(media, "photo", None) or media
    if info["kind"] == "document":
        return t.InputDocumentFileLocation(item.id, item.access_hash, item.file_reference, "")
    return t.InputPhotoFileLocation(item.id, item.access_hash, item.file_reference, info["variant"])


async def collect(client, media, *, max_requests=4096):
    """Return complete/partial/unavailable coverage; never call upload.getFile."""
    info = representation(media)
    result = {"format": FORMAT, "algorithm": "sha256", "representation": info,
              "status": "unavailable", "expected_bytes": info["bytes"] if info else None,
              "covered_bytes": 0, "ranges": [], "request_count": 0, "downloaded_bytes": 0}
    if not info or type(info["bytes"]) is not int or info["bytes"] <= 0:
        return {**result, "reason": "unsupported_representation_or_unknown_size"}
    target = location(media, info)
    sender, borrowed = client._sender, None
    offset, size = 0, info["bytes"]
    try:
        # getFileHashes may return LOCATION_INVALID on the account's DC instead
        # of FILE_MIGRATE. Use the observed media DC before the first request.
        current_dc = getattr(getattr(client, "session", None), "dc_id", None)
        if current_dc is not None and info["dc_id"] != current_dc:
            borrowed = await client._borrow_exported_sender(info["dc_id"])
            sender = borrowed
        while offset < size and result["request_count"] < max_requests and len(result["ranges"]) < MAX_RANGES:
            request = f.upload.GetFileHashesRequest(target, offset)
            try:
                result["request_count"] += 1
                batch = await client._call(sender, request)
            except errors.FileMigrateError as exc:
                if borrowed is not None:
                    await client._return_exported_sender(borrowed)
                    borrowed = None
                borrowed = await client._borrow_exported_sender(exc.new_dc)
                sender = borrowed
                if result["request_count"] >= max_requests:
                    break
                result["request_count"] += 1
                batch = await client._call(sender, request)
            if not batch:
                result["reason"] = "server_returned_no_hashes"
                break
            before = offset
            for part in sorted(batch, key=lambda row: row.offset):
                if (type(part.offset) is not int or type(part.limit) is not int or part.offset < 0
                        or part.limit <= 0 or not isinstance(part.hash, bytes) or len(part.hash) != 32):
                    raise ValueError("invalid_server_hash_range")
                if part.offset >= size:
                    break
                row = {"offset": part.offset, "length": part.limit, "sha256": part.hash.hex()}
                if part.offset < offset:
                    if row in result["ranges"]:
                        continue
                    raise ValueError("overlapping_server_hash_ranges")
                if part.offset != offset:
                    result["reason"] = "server_hash_coverage_gap"
                    break
                if len(result["ranges"]) >= MAX_RANGES:
                    break
                result["ranges"].append(row)
                offset = min(size, part.offset + part.limit)
            result["covered_bytes"] = offset
            if offset == before or result.get("reason"):
                break
        result["status"] = "complete" if offset == size else "partial" if offset else "unavailable"
        if offset != size:
            result.setdefault("reason", "hash_request_or_range_budget")
        return result
    finally:
        if borrowed is not None:
            await client._return_exported_sender(borrowed)


def compare(path, manifest):
    """Compare an existing local file; authenticity depends on trusted evidence."""
    from .verify import validate_server_hashes
    validate_server_hashes(manifest)
    path = Path(path)
    if not path.is_file():
        return {"status": "missing"}
    if manifest["status"] != "complete":
        return {"status": "incomplete_hash_coverage", "covered_bytes": manifest["covered_bytes"]}
    before = path.stat()
    if before.st_size != manifest["expected_bytes"]:
        return {"status": "different_size_or_representation"}
    mismatched = []
    with path.open("rb") as stream:
        for part in manifest["ranges"]:
            stream.seek(part["offset"])
            remaining = min(part["length"], manifest["expected_bytes"] - part["offset"])
            digest = hashlib.sha256()
            while remaining:
                block = stream.read(min(remaining, 1024 * 1024))
                if not block:
                    return {"status": "file_changed_during_comparison"}
                digest.update(block)
                remaining -= len(block)
            if digest.hexdigest() != part["sha256"]:
                mismatched.append(part["offset"])
    after = path.stat()
    if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        return {"status": "file_changed_during_comparison"}
    return {"status": "different" if mismatched else "match", "mismatched_offsets": mismatched,
            "compared_bytes": manifest["expected_bytes"], "ranges": len(manifest["ranges"])}


def main():
    parser = argparse.ArgumentParser(description="Compare a local file with a Telegram range-hash manifest.")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    if args.manifest.stat().st_size > 32 * 1024**2:
        parser.error("Hash manifest exceeds the size limit")
    result = compare(args.file, json.loads(args.manifest.read_bytes()))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "match" else 1)


if __name__ == "__main__":
    main()
