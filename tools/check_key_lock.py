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
        collectors[0].lock_key(client(key))
        collectors[0].lock_key(client(key))
        try:
            collectors[1].lock_key(client(key))
        except KeyInUse:
            pass
        else:
            raise AssertionError("Two workspaces must not connect the same session key")
        collectors[0].unlock_key()
        collectors[1].lock_key(client(key))
        collectors[1].unlock_key()
        collectors[0].lock_key(client(None))
        assert collectors[0].key_lock is None, "A login without a key yet takes no lock"
    finally:
        for store in stores:
            store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="key-lock-") as temporary:
        check(Path(temporary))
    print("One session key, one connection: a second process or workspace is refused until the first disconnects.")
