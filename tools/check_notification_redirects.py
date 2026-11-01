"""Notification redirect regression using real Apprise/Requests and an in-memory HTTP adapter.

No notifications, DNS lookups or network requests leave this process. Run from a
checkout with runtime dependencies: python tools/check_notification_redirects.py.
"""
import base64
import json
import logging
from pathlib import Path
import sys
from unittest.mock import patch
from urllib.parse import parse_qs, quote, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import apprise
import requests

from tgwitness import alerts
from tgwitness.network import NetworkConfig, NoRoute


class SyntheticHTTP:
    """Only these reserved example hosts exist; HTTP responses stay in memory."""

    def __init__(self):
        self.calls = []
        self.status = 302
        self.same_origin = False

    def send(self, request, **options):
        parsed = urlsplit(request.url)
        assert parsed.hostname in {"notify.example", "receiver.example"}, request.url
        self.calls.append({"url": request.url, "headers": dict(request.headers),
                           "body": request.body, "options": options})
        response = requests.Response()
        response.status_code = 200
        response.reason = "OK"
        response.url, response.request = request.url, request
        response._content, response._content_consumed = b"{}", True
        response.headers["Content-Type"] = "application/json"
        if parsed.hostname == "notify.example" and parsed.path.startswith("/redirect/"):
            response.status_code, response.reason = self.status, "Synthetic redirect"
            host = "notify.example" if self.same_origin else "receiver.example"
            response.headers["Location"] = "http://" + host + "/received"
        return response


def destination(path, redirect=None, basic=False):
    values = {"+X-Synthetic-Token": "SYNTHETIC_CUSTOM_TOKEN", "-api_key": "SYNTHETIC_QUERY_TOKEN"}
    if not basic:
        values["+Authorization"] = "Bearer SYNTHETIC_BEARER_TOKEN"
    if redirect is not None:
        values["redirect"] = redirect
    credentials = "synthetic-user:synthetic-password@" if basic else ""
    return "json://" + credentials + "notify.example" + path + "?" + urlencode(values, quote_via=quote)


def run():
    logging.getLogger("apprise").setLevel(logging.CRITICAL)
    transport = SyntheticHTTP()
    direct = NetworkConfig(kind="direct")
    original_merge = requests.Session.merge_environment_settings

    def send(_adapter, request, **options):
        return transport.send(request, **options)

    with patch.object(requests.adapters.HTTPAdapter, "send", send), \
            patch("requests.sessions.get_netrc_auth", return_value=None), \
            patch("socket.getaddrinfo", side_effect=AssertionError("A synthetic notification tried DNS")):
        # Negative control: the installed library follows explicit redirect=yes
        # and forwards the custom token to another origin without our policy.
        unsafe = apprise.Apprise()
        assert unsafe.add(destination("/redirect/negative-control", "yes"))
        unsafe.notify(body="Synthetic body", title="Synthetic title")
        forwarded = [row for row in transport.calls if urlsplit(row["url"]).hostname == "receiver.example"]
        assert forwarded and forwarded[0]["headers"].get("X-Synthetic-Token") == "SYNTHETIC_CUSTOM_TOKEN"

        # Normal delivery preserves the original path and configured credentials.
        for basic in (False, True):
            transport.calls.clear()
            result = alerts.deliver([destination("/notify/explicit-path", "yes", basic)],
                                    "Synthetic title", "Synthetic body", direct)
            assert result["sent"] == 1 and result["failed"] == 0, result
            assert len(transport.calls) == 1
            call = transport.calls[0]
            parsed = urlsplit(call["url"])
            assert parsed.path == "/notify/explicit-path"
            assert parse_qs(parsed.query) == {"api_key": ["SYNTHETIC_QUERY_TOKEN"]}
            expected = ("Basic " + base64.b64encode(b"synthetic-user:synthetic-password").decode()
                        if basic else "Bearer SYNTHETIC_BEARER_TOKEN")
            assert call["headers"].get("Authorization") == expected, call["headers"]
            assert call["headers"].get("X-Synthetic-Token") == "SYNTHETIC_CUSTOM_TOKEN"
            assert json.loads(call["body"])["message"] == "Synthetic body"
            assert call["options"]["proxies"] == {}, "The workspace direct route changed"

        checked = 0
        for status in (301, 302, 303, 307, 308):
            transport.status = status
            for override in (None, "yes", "true", "1"):
                for basic in (False, True):
                    transport.calls.clear()
                    result = alerts.deliver([destination("/redirect/protected", override, basic)],
                                            "Synthetic title", "Synthetic body", direct)
                    assert result["sent"] == 0 and result["failed"] == 1, result
                    assert len(transport.calls) == 1, "A redirect forwarded notification credentials"
                    assert urlsplit(transport.calls[0]["url"]).hostname == "notify.example"
                    checked += 1

        # No exception exists for same-origin redirects either: the configured
        # destination must be the final URL, keeping the policy predictable.
        transport.same_origin = True
        transport.calls.clear()
        result = alerts.deliver([destination("/redirect/same-origin", "yes")], "Title", "Body", direct)
        assert result["failed"] == 1 and len(transport.calls) == 1

        # Existing refusal of disabled external routes still happens before HTTP.
        transport.calls.clear()
        result = alerts.deliver([destination("/notify/unused")], "Title", "Body", NoRoute(ValueError("Synthetic no route")))
        assert result["failed"] == 1 and not transport.calls
        result = alerts.deliver([destination("/notify/unused")], "Title", "Body", NetworkConfig(kind="mtproxy_auto"))
        assert result["failed"] == 1 and not transport.calls

    assert requests.Session.merge_environment_settings is original_merge
    print(f"PASS: {checked} cross-origin redirect cases blocked, explicit overrides blocked, "
          "normal header/basic/query/path delivery preserved; no network used.")


if __name__ == "__main__":
    run()
