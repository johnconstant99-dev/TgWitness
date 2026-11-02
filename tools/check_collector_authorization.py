import asyncio
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.collector import ACCOUNT_LOSS, Collector
from tgwitness.security import Vault
from tgwitness.store import Store


class Connection:
    def __init__(self):
        self.disconnected = False

    async def disconnect(self):
        self.disconnected = True


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        for error_type, telegram_error, cause in ACCOUNT_LOSS:
            collector = Collector(store, vault)
            current, stale = Connection(), Connection()
            collector.client, collector.running = current, True
            previous = store.get_setting('account_loss', None)
            generation = collector.authorization_generation
            assert collector.handle_authorization_error(error_type(request=None), 'stale RPC', client=stale)
            assert collector.running and collector.authorization_generation == generation
            assert store.get_setting('account_loss', None) == previous
            assert not current.disconnected and not stale.disconnected
            assert collector.handle_authorization_error(error_type(request=None), 'recheck', client=current)
            assert not collector.running and collector.authorization_required
            assert store.get_setting('account_loss')['cause'] == cause
            gap = next(event for event in store.events(limit=10) if event['kind'] == 'coverage.gap')
            assert gap['payload']['cause'] == cause and gap['payload']['telegram_error'] == telegram_error
            assert gap['payload']['operation'] == 'recheck'
            assert collector.handle_authorization_error(error_type(request=None), 'duplicate RPC', client=current)
            await collector.wait_authorization_cleanup()
            assert current.disconnected and not stale.disconnected
        gaps = [event for event in store.all_events() if event['kind'] == 'coverage.gap']
        assert len(gaps) == len(ACCOUNT_LOSS), 'One coverage gap per rejected connection'
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='collector-authorization-') as temporary:
        asyncio.run(check(Path(temporary)))
    print('Account-loss causes, stale connections, duplicate errors, worker cleanup and signatures passed.')
