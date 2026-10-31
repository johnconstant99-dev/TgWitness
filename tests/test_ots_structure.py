"""Reject malformed OTS proofs and embedded markers."""
import pytest

from tgwitness.verify import OTS_BITCOIN, OTS_MAGIC, OTS_PENDING, ots_summary


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def attestation(tag, payload):
    return b"\x00" + tag + varint(len(payload)) + payload


DIGEST = bytes(range(32))
URI = b"https://calendar.example"
PENDING = attestation(OTS_PENDING, varint(len(URI)) + URI)
BITCOIN = attestation(OTS_BITCOIN, varint(850000))


def summary(tree):
    return ots_summary(OTS_MAGIC + b"\x01\x08" + DIGEST + tree, DIGEST)


def test_structured_pending_and_bitcoin_remain_explicitly_unverified():
    assert summary(PENDING)["status"] == "pending"
    result = summary(b"\xf0\x01x\x08" + BITCOIN)
    assert result == {"status": "bitcoin-unverified", "verification": "structure only; run ots verify"}
    assert summary(b"\xff" + PENDING + b"\x08" + BITCOIN) == result


def test_marker_in_argument_or_unknown_payload_is_not_a_bitcoin_attestation():
    assert summary(b"\xf0\x08" + OTS_BITCOIN + PENDING)["status"] == "pending"
    assert summary(attestation(b"unknown!", OTS_BITCOIN + OTS_PENDING))["status"] == "unknown"


@pytest.mark.parametrize("tree", [
    b"", OTS_BITCOIN, b"garbage" + OTS_BITCOIN,
    b"\x00" + OTS_BITCOIN, BITCOIN[:-1], PENDING[:-1],
    PENDING + OTS_BITCOIN, b"\xff" + PENDING,
    b"\xff\xff" + PENDING, b"\x09" + PENDING,
    b"\xf0\x00" + PENDING,
    attestation(OTS_BITCOIN, b"\x80"),
    attestation(OTS_BITCOIN, varint(2**32)),
    attestation(OTS_BITCOIN, varint(850000) + b"x"),
    attestation(OTS_PENDING, b"\x05x"),
    attestation(OTS_PENDING, b"\x01@"),
    b"\x02" + BITCOIN,
    b"\xff\x08" + PENDING + b"\x08" + PENDING,
    b"\xf3" * 8 + PENDING,
    b"\x08" * 256 + PENDING,
    b"\xf0" + varint(4097) + b"x" * 4097 + PENDING,
    b"\x00" + OTS_PENDING + b"\x80" * 20,
])
def test_malformed_or_excessive_trees_are_rejected(tree):
    with pytest.raises(ValueError):
        summary(tree)


def test_width_and_total_size_are_bounded():
    with pytest.raises(ValueError, match="operation limit"):
        summary((b"\xff" + PENDING) * 10001 + PENDING)
    with pytest.raises(ValueError, match="size limit"):
        summary(b"x" * (1024 * 1024))


def test_every_truncation_of_branched_proof_fails():
    tree = b"\xff" + PENDING + b"\xf0\x01x\x08" + BITCOIN
    for end in range(len(tree)):
        with pytest.raises(ValueError):
            summary(tree[:end])
