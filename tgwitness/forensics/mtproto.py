import hashlib
import hmac
import secrets
import sqlite3
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAX_FRAME_BYTES = 16 * 1024 * 1024


class MTProtoFrameError(ValueError):
    pass


class AuthKeyNotFound(ValueError):
    pass


def _ecb(key):
    return Cipher(algorithms.AES(key), modes.ECB())


def ige_decrypt(ciphertext, key, iv):
    if len(ciphertext) % 16:
        raise MTProtoFrameError("Ciphertext length is not a multiple of 16")
    if len(key) != 32 or len(iv) != 32:
        raise MTProtoFrameError("AES-256-IGE needs a 32-byte key and a 32-byte iv")
    decryptor = _ecb(key).decryptor()
    iv1, iv2 = iv[:16], iv[16:32]
    out = bytearray()
    for index in range(0, len(ciphertext), 16):
        block = ciphertext[index:index + 16]
        decrypted = decryptor.update(bytes(a ^ b for a, b in zip(block, iv2)))
        plain = bytes(a ^ b for a, b in zip(decrypted, iv1))
        out.extend(plain)
        iv1, iv2 = block, plain
    return bytes(out)


def ige_encrypt(plaintext, key, iv):
    if len(plaintext) % 16:
        raise MTProtoFrameError("Plaintext length is not a multiple of 16")
    if len(key) != 32 or len(iv) != 32:
        raise MTProtoFrameError("AES-256-IGE needs a 32-byte key and a 32-byte iv")
    encryptor = _ecb(key).encryptor()
    iv1, iv2 = iv[:16], iv[16:32]
    out = bytearray()
    for index in range(0, len(plaintext), 16):
        block = plaintext[index:index + 16]
        encrypted = encryptor.update(bytes(a ^ b for a, b in zip(block, iv1)))
        cipher = bytes(a ^ b for a, b in zip(encrypted, iv2))
        out.extend(cipher)
        iv1, iv2 = cipher, block
    return bytes(out)


def auth_key_id(auth_key):
    return hashlib.sha1(auth_key).digest()[-8:]


def derive_keys(auth_key, msg_key, from_server):
    if len(auth_key) != 256 or len(msg_key) != 16:
        raise MTProtoFrameError("MTProto 2.0 needs a 256-byte authorization key and 16-byte message key")
    x = 8 if from_server else 0
    sha256_a = hashlib.sha256(msg_key + auth_key[x:x + 36]).digest()
    sha256_b = hashlib.sha256(auth_key[x + 40:x + 76] + msg_key).digest()
    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]
    return aes_key, aes_iv


def message_key(auth_key, plaintext, from_server):
    x = 8 if from_server else 0
    return hashlib.sha256(auth_key[x + 88:x + 120] + plaintext).digest()[8:24]


def extract_auth_key(session_path):
    path = Path(session_path)
    if not path.exists():
        raise AuthKeyNotFound("No Telethon session at " + str(path))
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        row = connection.execute("SELECT auth_key FROM sessions WHERE auth_key IS NOT NULL").fetchone()
    except sqlite3.DatabaseError as error:
        raise AuthKeyNotFound("Not a readable Telethon session: " + type(error).__name__) from None
    finally:
        connection.close()
    if not row or not row[0]:
        raise AuthKeyNotFound("The session holds no auth_key: " + str(path))
    key = bytes(row[0])
    if len(key) != 256:
        raise AuthKeyNotFound("auth_key is " + str(len(key)) + " bytes, expected 256")
    return key


class MTProtoDecryptor:
    def __init__(self, auth_key):
        if len(auth_key) != 256:
            raise MTProtoFrameError("auth_key must be exactly 256 bytes")
        self.auth_key = bytes(auth_key)
        self.auth_key_id = auth_key_id(self.auth_key)

    def decrypt_frame(self, frame, from_server=True):
        if not isinstance(frame, bytes) or len(frame) < 72:
            raise MTProtoFrameError("Frame shorter than an MTProto 2.0 envelope")
        if len(frame) > MAX_FRAME_BYTES:
            raise MTProtoFrameError("Frame exceeds the offline parser limit")
        if frame[:8] != self.auth_key_id:
            raise MTProtoFrameError("Frame auth_key_id does not match this session")
        msg_key = frame[8:24]
        ciphertext = frame[24:]
        if len(ciphertext) % 16:
            raise MTProtoFrameError("Encrypted body is not a multiple of 16")
        aes_key, aes_iv = derive_keys(self.auth_key, msg_key, from_server)
        plaintext = ige_decrypt(ciphertext, aes_key, aes_iv)
        if not hmac.compare_digest(message_key(self.auth_key, plaintext, from_server), msg_key):
            raise MTProtoFrameError("Integrity check failed: msg_key does not match the plaintext")
        salt, session_id, message_id, seq_no, length = struct.unpack("<QQQii", plaintext[:32])
        if length < 4 or length % 4 or 32 + length > len(plaintext):
            raise MTProtoFrameError("Declared payload length falls outside the decrypted body")
        padding_length = len(plaintext) - 32 - length
        if not 12 <= padding_length <= 1024:
            raise MTProtoFrameError("MTProto 2.0 padding must contain 12 to 1024 bytes")
        if seq_no < 0 or message_id == 0 or (message_id % 4 not in (1, 3) if from_server else message_id % 4 != 0):
            raise MTProtoFrameError("Invalid message identifier or sequence number for this direction")
        return {"auth_key_id": self.auth_key_id.hex(), "salt": salt, "session_id": session_id,
                "message_id": message_id, "seq_no": seq_no, "payload_len": length, "from_server": from_server,
                "payload": plaintext[32:32 + length], "payload_sha256": hashlib.sha256(plaintext[32:32 + length]).hexdigest()}

    def encrypt_frame(self, payload, *, from_server=True, salt=0, session_id=0, message_id=None, seq_no=0, padding=None):
        if not isinstance(payload, bytes) or len(payload) < 4 or len(payload) % 4:
            raise MTProtoFrameError("MTProto payloads must contain a four-byte-aligned TL object")
        if message_id is None:
            message_id = 1 if from_server else 4
        if seq_no < 0 or message_id == 0 or (message_id % 4 not in (1, 3) if from_server else message_id % 4 != 0):
            raise MTProtoFrameError("Invalid message identifier or sequence number for this direction")
        body = struct.pack("<QQQii", salt, session_id, message_id, seq_no, len(payload)) + payload
        if padding is None:
            padding = secrets.token_bytes(-(len(body) + 12) % 16 + 12)
        if not 12 <= len(padding) <= 1024 or (len(body) + len(padding)) % 16:
            raise MTProtoFrameError("MTProto 2.0 padding must contain 12 to 1024 bytes and align the body")
        body += padding
        if len(body) + 24 > MAX_FRAME_BYTES:
            raise MTProtoFrameError("Frame exceeds the offline parser limit")
        msg_key = message_key(self.auth_key, body, from_server)
        aes_key, aes_iv = derive_keys(self.auth_key, msg_key, from_server)
        return self.auth_key_id + msg_key + ige_encrypt(body, aes_key, aes_iv)
