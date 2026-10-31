import asyncio

import pytest
from tgwitness import security
from tgwitness.proxy_catalog import ProxyPool
from tgwitness.security import Vault
from tgwitness.store import Store

REAL_OWNER_ONLY = security.owner_only


@pytest.fixture(autouse=True)
def quick_owner_only(monkeypatch):

    monkeypatch.setattr(security, "owner_only", lambda root: None)


@pytest.fixture(autouse=True)
def local_destinations(monkeypatch):

    monkeypatch.setenv("TGWITNESS_ALLOW_PRIVATE_DESTINATIONS", "1")


@pytest.fixture(autouse=True)
def offline_proxy_pool(monkeypatch):


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
