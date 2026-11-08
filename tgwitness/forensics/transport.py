import struct
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ABRIDGED_TAG = b"\xef"
INTERMEDIATE_TAG = b"\xee\xee\xee\xee"
PADDED_TAG = b"\xdd\xdd\xdd\xdd"
FULL = "full"
ABRIDGED = "abridged"
INTERMEDIATE = "intermediate"
PADDED_INTERMEDIATE = "padded_intermediate"
MAX_PACKET_BYTES = 16 * 1024 * 1024 + 15


class TransportError(ValueError):
    pass


def _ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()


class ObfuscatedStream:
    def __init__(self, key, iv):
        self._cipher = _ctr(key, iv)

    def process(self, data):
        return self._cipher.update(data)


def keys_from_init(init):
    if len(init) != 64:
        raise TransportError("The obfuscated init packet must be 64 bytes")
    temp = init[8:56]
    send_key, send_iv = temp[:32], temp[32:48]
    reverse = init[55:7:-1]
    recv_key, recv_iv = reverse[:32], reverse[32:48]
    return (send_key, send_iv), (recv_key, recv_iv)


def protocol_tag(transport):
    return {ABRIDGED: ABRIDGED_TAG * 4, INTERMEDIATE: INTERMEDIATE_TAG,
            PADDED_INTERMEDIATE: PADDED_TAG}[transport]


def build_init(transport, body56):
    if len(body56) != 56:
        raise TransportError("Provide 56 random bytes for the init body")
    init = bytearray(body56 + b"\x00" * 8)
    init[56:60] = protocol_tag(transport)
    (send_key, send_iv), _ = keys_from_init(bytes(init))
    encrypted = ObfuscatedStream(send_key, send_iv).process(bytes(init))
    init[56:64] = encrypted[56:64]
    return bytes(init)


class ObfuscatedSender:
    def __init__(self, transport, body56):
        if len(body56) != 56:
            raise TransportError("Provide 56 bytes for the init body")
        plaintext = bytearray(body56 + b"\x00" * 8)
        plaintext[56:60] = protocol_tag(transport)
        (send_key, send_iv), _ = keys_from_init(bytes(plaintext))
        self._stream = ObfuscatedStream(send_key, send_iv)
        encrypted = self._stream.process(bytes(plaintext))
        self.init = bytes(plaintext[:56]) + encrypted[56:64]

    def process(self, data):
        return self._stream.process(data)


def deobfuscate(stream_bytes, from_client):
    if len(stream_bytes) < 64:
        raise TransportError("Stream shorter than the 64-byte init")
    init = stream_bytes[:64]
    send, recv = keys_from_init(init)
    stream = ObfuscatedStream(*send)
    decoded_init = stream.process(init)
    tag = decoded_init[56:60]
    transport = {ABRIDGED_TAG * 4: ABRIDGED, INTERMEDIATE_TAG: INTERMEDIATE,
                 PADDED_TAG: PADDED_INTERMEDIATE}.get(tag)
    if transport is None:
        raise TransportError("Unknown obfuscated transport tag; MTProxy secrets are not supported")
    if not from_client:
        stream = ObfuscatedStream(*recv)
    body = stream.process(stream_bytes[64:])
    return transport, body


def frame_intermediate(payload):
    return struct.pack("<I", len(payload)) + payload


def unframe_intermediate(stream):
    offset = 0
    while offset < len(stream):
        if offset + 4 > len(stream):
            raise TransportError("Truncated intermediate length")
        (length,) = struct.unpack_from("<I", stream, offset)
        offset += 4
        if not 0 < length <= MAX_PACKET_BYTES or offset + length > len(stream):
            raise TransportError("Truncated intermediate frame")
        yield stream[offset:offset + length]
        offset += length


def frame_abridged(payload):
    if len(payload) % 4:
        raise TransportError("Abridged payloads are 4-byte aligned")
    words = len(payload) // 4
    if words < 0x7F:
        header = bytes([words])
    else:
        header = b"\x7f" + struct.pack("<I", words)[:3]
    return header + payload


def unframe_abridged(stream):
    offset = 0
    while offset < len(stream):
        first = stream[offset]
        offset += 1
        if first == 0 or first > 0x7F:
            raise TransportError("Unsupported abridged control packet or invalid length")
        if first < 0x7F:
            words = first
        else:
            if offset + 3 > len(stream):
                raise TransportError("Truncated abridged length")
            words = struct.unpack("<I", stream[offset:offset + 3] + b"\x00")[0]
            offset += 3
            if words < 0x7F:
                raise TransportError("Invalid extended abridged length")
        length = words * 4
        if length > MAX_PACKET_BYTES or offset + length > len(stream):
            raise TransportError("Truncated abridged frame")
        yield stream[offset:offset + length]
        offset += length


def frame_full(payload, seq_no):
    body = struct.pack("<II", len(payload) + 12, seq_no) + payload
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def unframe_full(stream):
    offset = 0
    expected_seq = None
    while offset < len(stream):
        if offset + 12 > len(stream):
            raise TransportError("Truncated full frame")
        (length,) = struct.unpack_from("<I", stream, offset)
        if not 12 < length <= MAX_PACKET_BYTES + 12 or offset + length > len(stream):
            raise TransportError("Truncated or invalid full frame")
        block = stream[offset:offset + length]
        payload, checksum = block[8:-4], struct.unpack("<I", block[-4:])[0]
        if zlib.crc32(block[:-4]) & 0xFFFFFFFF != checksum:
            raise TransportError("Full-transport CRC32 mismatch")
        seq = struct.unpack_from("<I", block, 4)[0]
        if expected_seq is not None and seq != expected_seq:
            raise TransportError("Full-transport sequence gap")
        expected_seq = (seq + 1) & 0xFFFFFFFF
        yield payload
        offset += length


def unframe_padded(stream):
    for packet in unframe_intermediate(stream):
        if len(packet) < 72 or packet[:8] == b"\x00" * 8:
            raise TransportError("Padded framing requires an encrypted MTProto envelope")
        length = 24 + ((len(packet) - 24) // 16) * 16
        yield packet[:length]


def unframe(stream, transport):
    if transport == INTERMEDIATE:
        return unframe_intermediate(stream)
    if transport == PADDED_INTERMEDIATE:
        return unframe_padded(stream)
    if transport == ABRIDGED:
        return unframe_abridged(stream)
    if transport == FULL:
        return unframe_full(stream)
    raise TransportError("Unknown transport: " + str(transport))


def encrypted_frames(frames):
    for frame in frames:
        if len(frame) < 8:
            raise TransportError("Truncated MTProto key identifier")
        if frame[:8] != b"\x00" * 8:
            if len(frame) < 72 or (len(frame) - 24) % 16:
                raise TransportError("Truncated encrypted MTProto envelope")
            yield frame
        else:
            if len(frame) < 24:
                raise TransportError("Truncated unencrypted MTProto envelope")
            length = struct.unpack_from("<i", frame, 16)[0]
            if length < 4 or length % 4 or len(frame) != 20 + length:
                raise TransportError("Invalid unencrypted MTProto envelope length")
