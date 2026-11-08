import hashlib
from pathlib import Path

from .indicators import Indicators

MAX_BYTES = 25 * 1024 * 1024
MAX_PIXELS = 50_000_000
MAX_PAYLOAD = 4096
MAX_SCAN = 200
IMAGE_TYPES = ("image/png", "image/jpeg", "image/webp", "image/bmp")
MEANING = ("Codes read from a saved image by this workspace. The text is what the code encodes; whether the address or "
           "link behind it belongs to anyone in particular is a separate question.")
UNAVAILABLE = ("Reading codes needs OpenCV, which is not installed with TgWitness. Install the optional extra "
               "tgwitness[qr] on the collector host, or read the code in another tool and record the result by hand.")


def reader():
    try:
        import cv2
    except ImportError:
        return None
    return cv2


def decode(data):
    cv2 = reader()
    if cv2 is None:
        raise LookupError(UNAVAILABLE)
    import numpy
    if len(data) > MAX_BYTES:
        raise ValueError("The image is larger than 25 MB.")
    picture = cv2.imdecode(numpy.frombuffer(data, dtype=numpy.uint8), cv2.IMREAD_COLOR)
    if picture is None:
        raise ValueError("This file is not an image OpenCV can read.")
    height, width = picture.shape[:2]
    if height * width > MAX_PIXELS:
        raise ValueError("The image is too large to scan.")
    detector = cv2.QRCodeDetector()
    try:
        ok, texts, points, _ = detector.detectAndDecodeMulti(picture)
    except cv2.error:
        ok, texts, points = False, (), None
    found = []
    if ok:
        for index, text in enumerate(texts):
            if not text:
                continue
            box = points[index] if points is not None and index < len(points) else None
            found.append({"text": text[:MAX_PAYLOAD], "truncated": len(text) > MAX_PAYLOAD,
                          "box": [[int(round(float(x))), int(round(float(y)))] for x, y in box] if box is not None else None})
    return found


def indicators_of(found, ref, at):
    reader = Indicators()
    for item in found:
        reader.text(item["text"], "qr code", ref, at)
    return reader.result()["items"]


def record(store, sha256, found, ref, at, chat_id=None, message_id=None):
    items = indicators_of(found, ref, at)
    payload = {"media_sha256": sha256, "codes": [{k: v for k, v in item.items() if v is not None} for item in found],
               "indicators": [{key: item[key] for key in ("kind", "value", "chain", "address", "amount", "token",
                                                          "token_contract", "normalized", "checksum")
                               if item.get(key) is not None} for item in items],
               "engine": "opencv", "meaning": MEANING}
    return store.append("media.qr_decoded", payload, chat_id, message_id)


def saved_images(store, chat_id=None, limit=MAX_SCAN):
    done = {(event.get("payload") or {}).get("media_sha256")
            for event in store.events(kind="media.qr_decoded", chat_id=chat_id, limit=5000)}
    found = []
    for event in store.events(kind="media.saved", chat_id=chat_id, limit=5000):
        payload = event.get("payload") or {}
        digest = payload.get("media_sha256")
        if not isinstance(digest, str) or digest in done or str(payload.get("mime_type") or "") not in IMAGE_TYPES:
            continue
        done.add(digest)
        found.append({"sha256": digest, "chat_id": event.get("chat_id"), "message_id": event.get("message_id"),
                      "ref": {"seq": event["seq"], "hash": event.get("hash")}, "at": event.get("observed_at")})
        if len(found) >= limit:
            break
    return found


def bytes_of(root, sha256):
    path = Path(root) / sha256
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
        return None
    data = path.read_bytes()
    return data if hashlib.sha256(data).hexdigest() == sha256 else None


def scan(store, media_root, chat_id=None, limit=MAX_SCAN):
    if reader() is None:
        raise LookupError(UNAVAILABLE)
    images, scanned, codes, failed = saved_images(store, chat_id, limit), 0, 0, {}
    for image in images:
        data = bytes_of(media_root, image["sha256"])
        if data is None:
            failed[image["sha256"]] = "file_missing"
            continue
        try:
            found = decode(data)
        except ValueError as exc:
            failed[image["sha256"]] = str(exc)
            continue
        scanned += 1
        if found:
            codes += len(found)
            record(store, image["sha256"], found, image["ref"], image["at"], image["chat_id"], image["message_id"])
    return {"images": len(images), "scanned": scanned, "codes": codes, "failed": failed}


def listing(store, chat_id=None, limit=500):
    found = []
    for event in store.events(kind="media.qr_decoded", chat_id=chat_id, limit=limit):
        payload = event.get("payload") or {}
        found.append({"record": event["seq"], "at": event.get("observed_at"), "chat_id": event.get("chat_id"),
                      "message_id": event.get("message_id"), "media_sha256": payload.get("media_sha256"),
                      "codes": payload.get("codes") or [], "indicators": payload.get("indicators") or []})
    return found


def register(app, authenticate, require_live, visible_chats, media_root):
    import asyncio

    from fastapi import Depends, HTTPException, Request

    def allowed(request, chat_id):
        chats = visible_chats(request)
        if chats is not None and (chat_id is None or chat_id not in chats):
            raise HTTPException(403, "This chat is not open to this access.")

    async def call(function, *args):
        try:
            return await asyncio.to_thread(function, *args)
        except LookupError as exc:
            raise HTTPException(503, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.get("/api/qr", dependencies=[Depends(authenticate)])
    async def codes(request: Request, chat_id: int | None = None):
        if chat_id is not None:
            allowed(request, chat_id)
        elif visible_chats(request) is not None:
            raise HTTPException(403, "Choose a chat this access can open.")
        return {"available": reader() is not None, "unavailable_reason": None if reader() else UNAVAILABLE,
                "codes": await call(listing, app.state.store, chat_id)}

    @app.post("/api/qr/scan", dependencies=[Depends(authenticate)])
    async def scan_images(request: Request, chat_id: int | None = None, limit: int = MAX_SCAN):
        require_live()
        if chat_id is not None:
            allowed(request, chat_id)
        elif visible_chats(request) is not None:
            raise HTTPException(403, "Choose a chat this access can open.")
        if not 1 <= limit <= MAX_SCAN:
            raise HTTPException(422, "Scan between 1 and %d images at a time." % MAX_SCAN)
        return await call(scan, app.state.store, media_root, chat_id, limit)
