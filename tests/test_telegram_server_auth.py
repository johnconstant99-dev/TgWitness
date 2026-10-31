"""The pinned Telethon dependency must reject unauthenticated server data."""
import asyncio
from collections import defaultdict
import logging
import struct

import pytest
from telethon.crypto import AuthKey, rsa
from telethon.errors import SecurityError
from telethon.network.authenticator import do_authentication
from telethon.network.mtprotostate import MTProtoState
from telethon.tl.functions import ReqPqMultiRequest
from telethon.tl.types import ResPQ


def test_unknown_server_key_cannot_establish_a_telegram_session():
    class UntrustedEndpoint:
        async def send(self, request):
            assert isinstance(request, ReqPqMultiRequest)
            return ResPQ(nonce=request.nonce, server_nonce=1, pq=b"\x0f",
                         server_public_key_fingerprints=[0])

    assert rsa.encrypt(0, b"synthetic handshake") is None
    with pytest.raises(SecurityError, match="could not find a valid key"):
        asyncio.run(do_authentication(UntrustedEndpoint()))


def test_redirected_endpoint_cannot_supply_arbitrary_encrypted_messages():
    # A disposable test key, unrelated to any Telegram account. Even knowing the
    # public key ID does not make arbitrary response bytes authenticate.
    key = AuthKey(bytes(range(256)))
    state = MTProtoState(key, defaultdict(lambda: logging.getLogger("synthetic-transport")))
    packet = struct.pack("<Q", key.key_id) + bytes(16) + bytes(64)
    with pytest.raises(SecurityError, match="msg_key doesn't match"):
        state.decrypt_message_data(packet)
