import asyncio
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store


class Connection:
    def __init__(self):
        self.connected = True

    def is_connected(self):
        return self.connected

    async def disconnect(self):
        self.connected = False


async def settle():
    for _ in range(5):
        await asyncio.sleep(0)


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        collector = Collector(store, vault)
        connection = collector.client = Connection()

        assert collector.reserve_export("scale")
        collector.release_export("scale")
        await settle()
        assert not connection.connected, "A paused account must not keep its connection after a one-off task"

        connection.connected = True
        collector.running = True
        assert not await collector.release_idle_connection()
        assert connection.connected, "Observation keeps the connection"
        collector.running = False

        collector.foreground = 1
        collector.close_when_idle()
        await settle()
        assert connection.connected, "A panel operation in flight keeps the connection"
        collector.foreground = 0

        assert collector.reserve_export("export")
        collector.close_when_idle()
        await settle()
        assert connection.connected, "A reserved task keeps the connection"
        collector.release_export("export")
        await settle()
        assert not connection.connected
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="idle-connection-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Paused accounts close their Telegram connection once no task or panel operation uses it.")
