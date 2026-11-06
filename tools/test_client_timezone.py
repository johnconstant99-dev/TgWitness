import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from telethon import TelegramClient
from telethon.sessions import MemorySession
from telethon.tl import types

from tgwitness import client_identity
from tgwitness.telegram_client import WitnessClient


@pytest.mark.parametrize("seconds, expected", [(0, 0), (450, 900), (-450, -900), (449, 0), (-449, 0),
    (20700, 20700), (-36000, -36000), (50400, 50400), (54000, -32400), (-46800, 39600)])
def test_desktop_timezone(seconds, expected):
    now = datetime(2026, 1, 1, tzinfo=timezone(timedelta(seconds=seconds)))
    assert client_identity.desktop_timezone(now) == expected


@pytest.mark.parametrize("lang_pack, supplied, expected", [
    ("tdesktop", {}, -28800), ("tdesktop", {"tz_offset": 0}, 0),
    ("android", {}, None), ("android", {"tz_offset": -36001}, -36001), ("", {}, None)])
def test_init_params_and_reconnect(monkeypatch, lang_pack, supplied, expected):
    async def scenario():
        client = WitnessClient(MemorySession(), 123, "a" * 32)
        client._init_request.lang_pack = lang_pack
        client._init_request.params = types.JsonObject([types.JsonObjectValue("other", types.JsonString("retained"))])
        client.tgwitness_client_profile = dict(supplied)
        connect = AsyncMock()
        monkeypatch.setattr(TelegramClient, "connect", connect)
        monkeypatch.setattr(client_identity, "desktop_timezone", lambda: -28800)
        await client.connect()
        values = {entry.key: entry.value.value for entry in client._init_request.params.value}
        assert values.get("tz_offset") == expected and values["other"] == "retained"
        monkeypatch.setattr(client_identity, "desktop_timezone", lambda: -25200)
        await client.connect()
        values = {entry.key: entry.value.value for entry in client._init_request.params.value}
        assert values.get("tz_offset") == (-25200 if lang_pack == "tdesktop" and not supplied else expected)
        assert len(values) == len(client._init_request.params.value)
        assert client.tgwitness_client_profile == supplied
        assert connect.await_count == 2
    asyncio.run(scenario())
