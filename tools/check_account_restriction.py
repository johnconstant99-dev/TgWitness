from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.errors import FrozenMethodInvalidError, PeerFloodError, UserRestrictedError

from tgwitness import interactions
from tgwitness.security import Vault
from tgwitness.store import Store


def refused(store):
    try:
        interactions.check_restriction(store)
    except interactions.AccountRestricted as exc:
        return str(exc)
    return None


def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        assert refused(store) is None
        interactions.note_restriction(store, ValueError("not a Telegram restriction"))
        assert refused(store) is None

        interactions.note_restriction(store, UserRestrictedError(request=None))
        text = refused(store)
        assert text and "spam block" in text and "until" in text, text
        held = store.get_setting("account_restriction")
        store.set_setting("account_restriction", {**held, "until": time.time() - 1})
        assert refused(store) is None and store.get_setting("account_restriction") is None

        interactions.note_restriction(store, PeerFloodError(request=None))
        assert "PEER_FLOOD" in refused(store)
        interactions.note_restriction(store, FrozenMethodInvalidError(request=None))
        assert "frozen" in refused(store) and store.get_setting("account_restriction")["until"] is None

        kinds = [e["kind"] for e in store.all_events()]
        assert kinds.count("account.restricted") == 3 and "account.restriction_expired" in kinds, kinds
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="account-restriction-") as temporary:
        check(Path(temporary))
    print("Spam block, PEER_FLOOD and frozen accounts turn risky actions off; timed limits lift by themselves.")
