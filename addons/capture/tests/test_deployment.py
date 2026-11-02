import json
from pathlib import Path

from tgwitness_capture.service import Config


def test_example_configs_are_valid_and_not_autostarted():
    root = Path(__file__).resolve().parents[1]
    browser = Config.load(root / "config/browser.example.json")
    ayugram = Config.load(root / "config/ayugram.example.json")
    assert browser.kind == "browser" and not browser.browser_url_prefix
    assert ayugram.kind == "ayugram" and not ayugram.video_input_args
    assert "enabled" not in json.loads((root / "config/browser.example.json").read_text())


def test_profiles_keys_and_proxy_boundaries():
    import yaml
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / "compose.yaml").read_text())
    services = compose["services"]
    assert all(service.get("profiles") for service in services.values())
    assert services["browser"]["networks"] == ["browser-internal"]
    assert compose["networks"]["browser-internal"]["internal"] is True
    assert services["browser-recorder"]["network_mode"] == "service:browser"
    assert services["browser-recorder"]["cap_drop"] == ["ALL"]
    assert "browser-records:/data" in services["browser-recorder"]["volumes"]
    assert "ayugram-records:/data" in services["ayugram-recorder"]["volumes"]
    assert not any("records" in str(mount) for mount in services["browser"]["volumes"])
    assert "never_direct allow all" in (root / "deploy/upstream-proxy.example.conf").read_text()
    assert not any("9222" in port for port in services["browser"]["ports"])
