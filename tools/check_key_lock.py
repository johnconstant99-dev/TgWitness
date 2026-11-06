import asyncio
from pathlib import Path
import secrets
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.collector import Collector
from tgwitness.security import KeyInUse, KeyLock, Vault
from tgwitness.store import Store


def client(key):
    return SimpleNamespace(session=SimpleNamespace(auth_key=SimpleNamespace(key=key)))


def check(root):
    key, other = secrets.token_bytes(256), secrets.token_bytes(256)
    first = KeyLock(key)
    try:
        KeyLock(key)
    except KeyInUse:
        pass
    else:
        raise AssertionError("A second holder of the same key must be refused")
    KeyLock(other).close()
    first.close()
    KeyLock(key).close()

    stores = []
    try:
        collectors = []
        for name in ("one", "two"):
            path = root / name
            vault, store = Vault(path), Store(path)
            store.bind(vault)
            stores.append(store)
            collectors.append(Collector(store, vault))
        first_client, second_client = client(key), client(other)
        collectors[0].lock_key(first_client)
        collectors[0].lock_key(first_client)
        try:
            collectors[0].lock_key(client(key))
        except KeyInUse:
            pass
        else:
            raise AssertionError("Two clients in one workspace must not connect the same session key")
        collectors[0].lock_key(second_client)
        try:
            collectors[1].lock_key(client(key))
        except KeyInUse:
            pass
        else:
            raise AssertionError("Two workspaces must not connect the same session key")
        collectors[0].unlock_key(second_client)
        KeyLock(other).close()
        try:
            KeyLock(key)
        except KeyInUse:
            pass
        else:
            raise AssertionError("Closing an independent client must retain the donor's lock")
        collectors[0].unlock_key(first_client)
        collectors[1].lock_key(client(key))
        collectors[1].unlock_key()
        collectors[0].lock_key(client(None))
        assert collectors[0].key_lock is None, "A login without a key yet takes no lock"
    finally:
        for store in stores:
            store.close()


async def check_route_reconnect(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    collector = Collector(store, vault)
    connection = client(secrets.token_bytes(256))
    connection.route_id = "synthetic-proxy"
    attempts = []

    async def ready():
        pass

    async def align(value):
        # Switching transport completes disconnect and releases this client's key.
        collector.connection_changed(value, "closed")

    async def rotate(*args):
        pass

    async def connect():
        try:
            other = KeyLock(connection.session.auth_key.key)
        except KeyInUse:
            pass
        else:
            other.close()
            raise AssertionError("The session key must be reserved before every transport connection")
        attempts.append(1)
        if len(attempts) == 1:
            collector.connection_changed(connection, "closed")
            raise OSError("Synthetic transport failure")
        collector.connection_changed(connection, "opened")

    collector.automatic = lambda: True
    collector.param = lambda name: 2
    collector.ensure_route = ready
    collector.align = align
    collector.rotate_route = rotate
    collector.pool = lambda: SimpleNamespace(succeeded=lambda route: None)
    connection.connect = connect
    try:
        await collector.connect_client(connection)
        assert len(attempts) == 2, "Both the first connection and retry must keep the key reserved"
    finally:
        collector.unlock_key()
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="key-lock-") as temporary:
        check(Path(temporary))
        asyncio.run(check_route_reconnect(Path(temporary) / "route"))
    print("One session key, one connection: a second process or workspace is refused until the first disconnects.")
