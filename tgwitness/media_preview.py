"""Recognize inert preview formats from bytes, never Telegram's supplied MIME type."""


def content_type(path):
    with path.open("rb") as source:
        head = source.read(512)
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"OggS"):
        return "audio/ogg"
    if head.startswith(b"ID3") or head[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "audio/mpeg"
    if head[4:8] == b"ftyp" and head[8:12] in (
            b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"M4V ", b"M4A ", b"qt  "):
        return "audio/mp4" if head[8:12] == b"M4A " else "video/mp4"
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    return "application/octet-stream"
