"""Bounded, offline reader for modern single-account Telegram Desktop TData ZIPs.

Format interpretation adapted from https://github.com/thedemons/opentele (1.15.1).
No Qt, third-party conversion service, archive extraction, or Telegram request.

MIT License
Copyright (c) 2022 thedemons

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import hashlib
import hmac
import io
import stat
import struct
import zipfile
from pathlib import PurePosixPath

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAX_EXPANDED = 32 * 1024**2
MAX_KEY_FILE = 64 * 1024


class Reader:
    def __init__(self, data):
        self.data, self.position = data, 0

    def take(self, count):
        if count < 0 or self.position + count > len(self.data):
            raise ValueError("Truncated TData structure.")
        value = self.data[self.position:self.position + count]
        self.position += count
        return value

    def number(self, format=">i"):
        return struct.unpack(format, self.take(struct.calcsize(format)))[0]

    def array(self):
        length = self.number(">I")
        return b"" if length == 0xFFFFFFFF else self.take(length)


def file_payload(data):
    if len(data) < 24 or data[:4] != b"TDF$":
        raise ValueError("Unsupported TData file header.")
    content = data[8:-16]
    digest = hashlib.md5(content + struct.pack("<I", len(content)) + data[4:8] + b"TDF$").digest()
    if not hmac.compare_digest(digest, data[-16:]):
        raise ValueError("TData file checksum failed.")
    return Reader(content)


def decrypt_local(data, key):
    """Decode Desktop's legacy local AES-IGE format, not an application password hash.

    SHA-1 combines an existing 256-byte key with the message key as required by
    that format. ECB supplies only the AES block primitive; the loop applies
    IGE chaining and verifies the plaintext message-key digest before returning.
    """
    if len(key) != 256 or len(data) < 32 or len(data) % 16:
        raise ValueError("Invalid encrypted TData structure.")
    message_key = data[:16]
    a = hashlib.sha1(message_key + key[8:40]).digest()
    b = hashlib.sha1(key[40:56] + message_key + key[56:72]).digest()
    c = hashlib.sha1(key[72:104] + message_key).digest()
    d = hashlib.sha1(message_key + key[104:136]).digest()
    aes_key = a[:8] + b[8:20] + c[4:16]
    iv = a[8:20] + b[:8] + c[16:20] + d[:8]
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB()).decryptor()
    previous_cipher, previous_plain = iv[:16], iv[16:]
    plain = bytearray()
    for offset in range(16, len(data), 16):
        block = data[offset:offset + 16]
        transformed = cipher.update(bytes(x ^ y for x, y in zip(block, previous_plain)))
        decoded = bytes(x ^ y for x, y in zip(transformed, previous_cipher))
        plain.extend(decoded)
        previous_cipher, previous_plain = block, decoded
    cipher.finalize()
    if not hmac.compare_digest(hashlib.sha1(plain).digest()[:16], message_key):
        raise ValueError("Cannot decrypt TData. Check the Desktop local passcode and archive integrity.")
    size = int.from_bytes(plain[:4], "little")
    if not 4 <= size <= len(plain) or len(plain) - size >= 16:
        raise ValueError("Invalid decrypted TData length.")
    return Reader(bytes(plain[4:size]))


def read_tdata_zip(payload, passcode=""):
    """Return (DC, auth key, claimed user ID); identity still needs online verification."""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if len(entries) > 512 or sum(e.file_size for e in entries) > MAX_EXPANDED:
                raise ValueError("TData archive exceeds 512 entries or 32 MiB expanded size.")
            names = {}
            for entry in entries:

                raw_name = entry.orig_filename
                path = PurePosixPath(raw_name)
                if (path.is_absolute() or ".." in path.parts or "\\" in raw_name or "\0" in raw_name
                        or ":" in raw_name or stat.S_ISLNK(entry.external_attr >> 16)
                        or entry.flag_bits & 1):
                    raise ValueError("Unsafe or encrypted ZIP entry. Supply an ordinary TData ZIP.")
                name = path.as_posix()
                if name in names:
                    raise ValueError("Duplicate TData archive entry.")
                names[name] = entry
            roots = {str(PurePosixPath(name).parent) for name in names
                     if PurePosixPath(name).name in ("key_datas", "key_data1", "key_data0")}
            if len(roots) != 1:
                raise ValueError("Expected one modern TData folder containing key_datas (or key_data0/1).")
            root = roots.pop()

            def read(name):
                for suffix in ("s", "1", "0"):
                    full = (PurePosixPath(root) / (name + suffix)).as_posix()
                    if full in names:
                        entry = names[full]
                        if entry.file_size > MAX_KEY_FILE or entry.is_dir():
                            raise ValueError("TData authorization file exceeds 64 KiB.")
                        with archive.open(entry) as incoming:
                            data = incoming.read(MAX_KEY_FILE + 1)
                        if len(data) > MAX_KEY_FILE:
                            raise ValueError("TData authorization file is too large.")
                        return file_payload(data)
                raise ValueError("TData authorization file is missing.")

            keys = read("key_data")
            salt, encrypted_key, encrypted_info = keys.array(), keys.array(), keys.array()
            if len(salt) != 32:
                raise ValueError("Unsupported TData salt.")
            password = passcode.encode("utf-8")
            # Desktop defines this SHA-512 preprocessing followed by PBKDF2.
            # It is import compatibility, not storage of passwords by TgWitness.
            seed = hashlib.sha512(salt + password + salt).digest()
            password_key = hashlib.pbkdf2_hmac("sha512", seed, salt, 100000 if password else 1, 256)
            local_key = decrypt_local(encrypted_key, password_key).take(256)
            info = decrypt_local(encrypted_info, local_key)
            if info.number() != 1:
                raise ValueError("Import one TData account at a time. Use separate session files for a multi-account folder.")
            index = info.number()
            if not 0 <= index < 3:
                raise ValueError("Unsupported TData account index.")
            data_name = "data" if index == 0 else "data#" + str(index + 1)
            part = "".join(f"{byte:02X}"[::-1] for byte in hashlib.md5(data_name.encode()).digest()[:8])
            mtp = decrypt_local(read(part).array(), local_key)
            if mtp.number() != 75:
                raise ValueError("Unsupported TData authorization block.")
            auth = Reader(mtp.array())
            user_id, dc = auth.number(), auth.number()
            if user_id == -1 and dc == -1:
                user_id, dc = auth.number(">Q"), auth.number()
            count = auth.number()
            if not 1 <= count <= 20 or user_id <= 0:
                raise ValueError("Invalid TData account or authorization count.")
            matching = []
            for _ in range(count):
                key_dc, key = auth.number(), auth.take(256)
                if key_dc == dc:
                    matching.append(key)
            if len(matching) != 1:
                raise ValueError("TData must contain exactly one authorization for its main DC.")
            return dc, matching[0], user_id
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, struct.error, EOFError):
        raise ValueError("Invalid or unsupported TData ZIP.") from None
