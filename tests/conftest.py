import asyncio

import pytest
from tgwitness.proxy_catalog import ProxyPool
from tgwitness.security import Vault
from tgwitness.store import Store


@pytest.fixture(autouse=True)
def local_destinations(monkeypatch):
    # Test servers listen on 127.0.0.1; refusing internal addresses has its own tests, which unset this.
    monkeypatch.setenv("TGWITNESS_ALLOW_PRIVATE_DESTINATIONS", "1")


@pytest.fixture(autouse=True)
def offline_proxy_pool(monkeypatch):
    # Automatic MTProxy, the default route, resolves and checks listed proxies and refreshes the lists
    # in the background; tests never contact them. test_proxy_pool.py covers these steps.
    async def pin(route, operator=False):
        return route

    async def handshake(route):
        return 40

    async def idle(self):
        await asyncio.Event().wait()
    monkeypatch.setattr(ProxyPool, "pin", staticmethod(pin))
    monkeypatch.setattr(ProxyPool, "probe", staticmethod(handshake))
    monkeypatch.setattr(ProxyPool, "run", idle)


@pytest.fixture
def journal(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    vault = Vault(tmp_path)
    store = Store(tmp_path)
    store.bind(vault)
    yield store, vault
    store.close()
