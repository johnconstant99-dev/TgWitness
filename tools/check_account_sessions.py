import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.tl import functions, types

from tgwitness.collector import Collector, ProtectedSession
from tgwitness.security import Vault
from tgwitness.store import Store

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)


def authorization(hash_, current, device):
    return types.Authorization(hash=hash_, device_model=device, platform="Desktop", system_version="Windows 10",
                               api_id=2040, app_name="Telegram Desktop", app_version="7.3.3", date_created=NOW,
                               date_active=NOW, ip="198.51.100." + str(hash_ % 200), country="Iceland",
                               region="Reykjavik", current=current)


class Client:
    def __init__(self):
        self.sessions = [authorization(11, True, "Workstation"), authorization(22, False, "Phone")]
        self.ended, self.passwords = [], []

    def is_connected(self):
        return True

    async def is_user_authorized(self):
        return True

    async def __call__(self, request):
        if isinstance(request, functions.account.GetAuthorizationsRequest):
            return types.account.Authorizations(authorization_ttl_days=180, authorizations=list(self.sessions))
        if isinstance(request, functions.account.ResetAuthorizationRequest):
            self.ended.append(request.hash)
            self.sessions = [s for s in self.sessions if s.hash != request.hash]
            return True
        raise AssertionError(request)

    async def edit_2fa(self, **options):
        self.passwords.append(options)
        return True


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        vault.save("credentials", {"api_id": 1, "api_hash": "0" * 32, "session": "imported-session"})
        store.set_setting("account", {"id": 42, "username": None, "key_origin": "imported"})
        collector = Collector(store, vault)
        client = collector.client = Client()
        collector.restore = lambda: asyncio.sleep(0)

        listed = await collector.account_sessions()
        assert [(s["hash"], s["current"]) for s in listed["sessions"]] == [("11", True), ("22", False)]
        assert all("ip" not in s for s in listed["sessions"])
        try:
            await collector.end_session("11")
        except ProtectedSession:
            pass
        else:
            raise AssertionError("The session TgWitness works on must not be ended")
        assert await collector.end_session("22") == {"ended": True} and client.ended == [22]
        await collector.change_password(None, "new secret", "hint")
        assert client.passwords == [{"current_password": None, "new_password": "new secret", "hint": "hint"}]
        kinds = [e["kind"] for e in store.all_events()]
        assert "account.session_ended" in kinds and "account.password_changed" in kinds and "account.sessions" in kinds
        assert "new secret" not in str(list(store.all_events()))
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="account-sessions-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Sessions are listed, other sessions end only on request, the working session cannot be ended, passwords are not kept.")
