import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock
import zipfile

import pytest
from telethon import errors, utils
from telethon.tl import functions as f, types as t

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.account_export import AccountExport, AccountExportOptions
from tgwitness.account_export_transport import Transport, WrappedClient
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import verify_account_export
from tools.demo_account_export import SyntheticCollector


CHAT = -1000000000123
ENTITY = t.Channel(id=123, title="Public synthetic", photo=t.ChatPhotoEmpty(),
                   date=datetime(2026, 1, 1, tzinfo=timezone.utc), broadcast=True,
                   username="synthetic_public", access_hash=42, left=True)


class SelectedClient:
    def __init__(self, *, archived=False, listed=False, known=True, failure=None):
        self.archived, self.listed, self.known, self.failure = archived, listed, known, failure
        self.calls = []

    @property
    def dialog_scans(self):
        return self.calls.count("dialogs")

    async def get_entity(self, peer):
        assert peer == CHAT
        if not self.known:
            raise ValueError("Peer not cached")
        return ENTITY

    async def get_input_entity(self, peer):
        return peer if isinstance(peer, (t.InputPeerChannel, t.InputPeerUser)) else utils.get_input_peer(ENTITY)

    async def _get_input_dialog(self, peer):
        assert isinstance(peer, t.InputDialogPeer)
        return peer

    async def get_me(self):
        return NS(id=70000)

    async def iter_dialogs(self, **kwargs):
        self.calls.append("dialogs")
        if self.listed:
            yield NS(entity=ENTITY, name=ENTITY.title, folder_id=1 if self.archived else 0)

    async def __call__(self, request, **kwargs):
        self.calls.append(request)
        while isinstance(request, (f.InvokeWithTakeoutRequest, f.InvokeWithMessagesRangeRequest)):
            request = request.query
        if isinstance(request, f.messages.GetSplitRangesRequest):
            return [t.MessageRange(min_id=0, max_id=100)]
        if isinstance(request, f.channels.GetLeftChannelsRequest):
            return t.messages.Chats(chats=[])
        if isinstance(request, f.messages.GetPeerDialogsRequest):
            if self.failure:
                raise self.failure
            return NS(dialogs=[NS(peer=t.PeerChannel(123), folder_id=1 if self.archived else 0)]
                      if self.listed else [], chats=[ENTITY], users=[])
        assert isinstance(request, f.messages.GetHistoryRequest), type(request).__name__
        messages = [t.Message(id=5, peer_id=t.PeerChannel(123), date=ENTITY.date, message="Synthetic")]
        return NS(messages=messages if request.offset_id == 0 or request.offset_id > 5 else [], users=[], chats=[ENTITY])


def network(tmp_path, client, **options):
    net = Transport(NS(client=client), Vault(tmp_path), "a" * 32,
                    AccountExportOptions(transport="regular", chat_ids=[CHAT], chat_kinds=["channel"],
                                         include_profile=False, include_contacts=False, **options).model_dump())
    net.client = WrappedClient(client)
    return net


def test_public_selection_does_not_require_a_join_or_dialog_scan(tmp_path):
    async def run():
        client = SelectedClient()
        chats, tasks, gaps = await network(tmp_path, client).discover()
        assert [c["id"] for c in chats] == [CHAT], "A readable selected public channel disappeared from the export"
        assert not gaps and len(tasks) == 1
        assert tasks[0]["cursor_start"] == 6 and tasks[0]["newest_message_id"] == 5
        assert client.dialog_scans == 0
        assert chats[0]["left"] and chats[0]["archived"] is None
        assert not any(isinstance(r, f.channels.JoinChannelRequest) for r in client.calls)
    asyncio.run(run())


@pytest.mark.parametrize("archived,include,selected", [(True, False, False), (False, False, True), (True, True, True)])
def test_selection_keeps_archive_filter(tmp_path, archived, include, selected):
    async def run():
        client = SelectedClient(archived=archived, listed=True)
        chats, tasks, gaps = await network(tmp_path, client, include_archived=include).discover()
        assert bool(chats) == selected and bool(tasks) == selected and not gaps
        assert client.dialog_scans == 0
    asyncio.run(run())


def test_unknown_archive_status_is_not_reported_as_unarchived(tmp_path):
    async def run():
        chats, tasks, gaps = await network(tmp_path, SelectedClient(), include_archived=False).discover()
        assert not chats and not tasks and any("archive status unavailable" in gap for gap in gaps)
    asyncio.run(run())


def test_uncached_peer_uses_existing_dialog_inventory(tmp_path):
    async def run():
        client = SelectedClient(known=False, listed=True)
        chats, tasks, gaps = await network(tmp_path, client).discover()
        assert len(chats) == len(tasks) == 1 and not gaps
        assert client.dialog_scans == 1
    asyncio.run(run())


@pytest.mark.parametrize("failure", [errors.FloodWaitError(None, 30), errors.FloodPremiumWaitError(None, 30),
                                    errors.AuthKeyUnregisteredError(None), OSError("disconnected")])
def test_connection_and_wait_errors_do_not_become_missing_chats(tmp_path, failure):
    async def run():
        client = SelectedClient(failure=failure)
        with pytest.raises(type(failure)):
            await network(tmp_path, client).discover()
        assert client.dialog_scans == 0
        assert len(client.calls) == 1
    asyncio.run(run())


def test_selected_public_channel_reaches_signed_desktop_json(tmp_path):
    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store, collector.client, collector.restore = store, SelectedClient(), AsyncMock()
        export = AccountExport(collector, store, vault)
        try:
            job = await export.start({"transport": "regular", "chat_ids": [CHAT], "chat_kinds": ["channel"],
                "include_contacts": False, "include_profile": False, "media_types": [], "export_format": "telegram_json"})
            await asyncio.wait_for(export.task, 30)
            assert export.public()["phase"] == "done", export.public()
            result = export.result_path(job["id"])
            assert verify_account_export(result)["counts"]["messages"] == 1
            with zipfile.ZipFile(result) as archive:
                desktop = json.loads(archive.read("result.json"))
                assert not desktop["chats"]["list"]
                chat = desktop["left_chats"]["list"][0]
                assert chat["id"] == 123 and chat["type"] == "public_channel"
                assert [row["id"] for row in chat["messages"]] == [5]
            assert collector.client.dialog_scans == 0
        finally:
            await export.close()
            store.close()
    asyncio.run(run())


def test_takeout_selection_keeps_split_inventory(tmp_path):
    async def run():
        client = SelectedClient(listed=True)
        client.get_entity = AsyncMock(side_effect=AssertionError("Takeout must retain its range inventory"))
        net = network(tmp_path, client)
        net.options["transport"] = "takeout"
        net.secret["takeout_id"] = 1
        net.client = WrappedClient(client, 1)
        chats, tasks, gaps = await net.discover()
        assert len(chats) == len(tasks) == 1 and not gaps
        assert tasks[0]["telegram_range"] == {"min_id": 0, "max_id": 100}
        assert client.dialog_scans == 1
        client.get_entity.assert_not_called()
    asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
