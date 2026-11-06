import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.tl import types

from tgwitness import ephemeral, message_details, pdf_report, report
from tgwitness.collector import Collector, auto_delete, plain
from tgwitness.security import Vault
from tgwitness.store import Store

CHANNEL = -1000000000666
DAY = 86400


def message(mid, age, ttl=DAY):
    return types.Message(mid, types.PeerChannel(666), date=datetime.now(timezone.utc) - timedelta(seconds=age),
                         message="Synthetic " + str(mid), from_id=types.PeerUser(91), ttl_period=ttl)


def deletion(ids):
    return SimpleNamespace(chat_id=CHANNEL, deleted_ids=ids, original_update=types.UpdateDeleteChannelMessages(
        channel_id=666, messages=ids, pts=1, pts_count=len(ids)))


def view_once(unread, out=False):
    photo = types.Photo(1, 2, b"ref", datetime(2026, 11, 5, tzinfo=timezone.utc), [types.PhotoSize("x", 20, 20, 10)], 2)
    return plain(types.Message(5, types.PeerUser(91), date=datetime(2026, 11, 5, tzinfo=timezone.utc), message="",
                               out=out, media_unread=unread,
                               media=types.MessageMediaPhoto(photo=photo, ttl_seconds=ephemeral.VIEW_ONCE)))


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        store.set_target(CHANNEL, "Watched group", "supergroup", True)
        collector = Collector(store, vault)
        collector.running = True
        await collector.capture_message(message(1, DAY - 30), "message.new", CHANNEL)
        await collector.capture_message(message(2, 3600), "message.new", CHANNEL)
        await collector.capture_message(message(3, DAY - 30, None), "message.new", CHANNEL)
        await collector.on_delete(deletion([1]))
        await collector.on_delete(deletion([2]))
        await collector.on_delete(deletion([3]))
        gone = {e["message_id"]: e for e in store.all_events() if e["kind"] == "message.deleted"}
        timer = gone[1]["payload"]["auto_delete"]
        assert timer["expected"] is True and timer["ttl_period"] == DAY, timer
        assert abs(timer["observed_after_expiry_seconds"] + 30) <= 5, timer
        assert gone[2]["payload"]["auto_delete"]["expected"] is False
        assert "auto_delete" not in gone[3]["payload"]
        shown = {m["message_id"]: m for m in store.chat_messages(CHANNEL)["messages"]}
        assert [shown[i]["auto_deleted"] for i in (1, 2, 3)] == [True, False, False]
        say = report.Words("en")
        assert "auto-delete timer expired" in report.record_html(gone[1], say, {}, {}, False)
        assert "reported this message as deleted" in report.record_html(gone[2], say, {}, {}, False)
        histories = report.message_histories(store.all_events(), {(CHANNEL, 1), (CHANNEL, 2)})
        assert histories[(CHANNEL, 1)]["gone"][0]["auto_delete"] is True
        assert "auto_delete" not in histories[(CHANNEL, 2)]["gone"][0]
        sent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        assert auto_delete({"ttl_period": DAY, "sent_at": sent}, datetime.now(timezone.utc).isoformat(), recheck=True)["expected"]
        assert not auto_delete({"ttl_period": DAY * 7, "sent_at": sent}, datetime.now(timezone.utc).isoformat(),
                               recheck=True)["expected"]
        store.verify(vault.public_key)
    finally:
        store.close()

    info = message_details.details(view_once(True))["media_info"]
    assert "self_destruct_seconds" not in info and info["ephemeral_media"]["observer_opened"] is False, info
    label = report.media_text(report.Words("en"), info)
    assert "View-once media · Not opened by the observing account" in label and str(ephemeral.VIEW_ONCE) not in label
    assert str(ephemeral.VIEW_ONCE) not in " ".join(pdf_report.details_lines(report.Words("en"), {"media_info": info}))
    assert message_details.details(view_once(False))["media_info"]["ephemeral_media"]["observer_opened"] is True
    assert "observer_opened" not in message_details.details(view_once(True, out=True))["media_info"]["ephemeral_media"]
    timed = plain(types.MessageMediaPhoto(photo=None, ttl_seconds=10))
    assert message_details.media_info(timed)["self_destruct_seconds"] == 10


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="auto-delete-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Deletions at the auto-delete moment are marked as expected; view-once media says whether the observer opened it.")
