import asyncio
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import health
from tgwitness.collector import Collector, ProtectedSession
from tgwitness.security import Vault
from tgwitness.store import Store


class Connection:
    def __init__(self):
        self.disconnected = False
        self.logged_out = False

    async def disconnect(self):
        self.disconnected = True

    def is_connected(self):
        return not self.disconnected

    async def log_out(self):
        self.logged_out = True
        return True


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        collector = Collector(store, vault)
        vault.save("credentials", {"api_id": 1, "api_hash": "0" * 32, "session": "imported-session"})
        store.set_setting("account", {"id": 42, "username": None, "key_origin": "imported"})
        connection = collector.client = Connection()
        try:
            await collector.sign_out()
        except ProtectedSession:
            pass
        else:
            raise AssertionError("Signing out an imported session must be refused")
        assert not connection.logged_out and not connection.disconnected
        assert vault.read("credentials").get("session") == "imported-session"

        assert await collector.forget_session() == {"telegram_session_ended": False, "forgotten": True}
        assert connection.disconnected and not connection.logged_out
        assert collector.client is None and "session" not in vault.read("credentials")
        forgotten = next(event for event in store.events(limit=5) if event["kind"] == "account.forgotten")
        assert forgotten["payload"]["account_id"] == 42 and forgotten["payload"]["telegram_session_ended"] is False

        vault.save("credentials", {"api_id": 1, "api_hash": "0" * 32, "session": "created-session"})
        store.set_setting("account", {"id": 43, "username": None, "key_origin": "created"})
        created = collector.client = Connection()
        assert (await collector.sign_out())["telegram_session_ended"] is True
        assert created.logged_out and created.disconnected
        lost = health.connection({"has_session": True, "running": False, "phase": "offline",
                                  "account_loss": {"cause": "session_duplicated"}}, None)
        assert (lost["state"], lost["reason"], lost["cause"]) == ("failed", "signed_out", "session_duplicated"), lost
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="protected-session-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Imported sessions refuse sign-out, forget keeps them alive in Telegram, created sessions still sign out.")
