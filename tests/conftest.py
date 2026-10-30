import pytest
from tgwitness.security import Vault
from tgwitness.store import Store


@pytest.fixture(autouse=True)
def local_destinations(monkeypatch):
    # Test servers listen on 127.0.0.1; refusing internal addresses has its own tests, which unset this.
    monkeypatch.setenv("TGWITNESS_ALLOW_PRIVATE_DESTINATIONS", "1")


@pytest.fixture
def journal(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    vault = Vault(tmp_path)
    store = Store(tmp_path)
    store.bind(vault)
    yield store, vault
    store.close()
