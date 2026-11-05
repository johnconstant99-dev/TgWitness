import base64
import socket
import socketserver
import threading

import pytest

from tgwitness_capture.gateway import Bridge, Handler, configuration, destination, connect_upstream


@pytest.mark.parametrize("target", ["localhost:443", "127.0.0.1:443", "[::1]:443", "169.254.169.254:443",
                                    "web.telegram.org:80", "web.telegram.org.evil:443", "evil:443",
                                    "web.telegram.org:443\r\nInjected: true", "web.telegram.org:0"])
def test_destination_boundaries(target):
    with pytest.raises(ValueError):
        destination(target)


def test_bridge_forwards_only_through_upstream_and_stops_on_failure():
    requests = []

    class Upstream(socketserver.StreamRequestHandler):
        def handle(self):
            headers = b""
            while True:
                line = self.rfile.readline()
                headers += line
                if line == b"\r\n" or not line:
                    break
            requests.append(headers)
            self.wfile.write(b"HTTP/1.1 200 OK\r\n\r\n")
            self.wfile.flush()
            data = self.rfile.read(4)
            self.wfile.write(data)

    upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    bridge = Bridge(("127.0.0.1", 0), Handler)
    bridge.upstream = configuration({"server": "http://127.0.0.1:" + str(upstream.server_address[1]),
                                     "username": "private-user", "password": "private-password"})
    worker = threading.Thread(target=bridge.serve_forever, daemon=True)
    worker.start()
    try:
        with socket.create_connection(bridge.server_address, timeout=3) as client:
            client.sendall(b"CONNECT web.telegram.org:443 HTTP/1.1\r\nHost: web.telegram.org:443\r\n\r\n")
            answer = client.recv(4096)
            assert b"200 Connection Established" in answer
            assert b"private" not in answer
            client.sendall(b"test")
            assert client.recv(4) == b"test"
        assert len(requests) == 1
        credential = base64.b64encode(b"private-user:private-password")
        assert credential in requests[0]
        upstream.shutdown()
        upstream.server_close()
        with socket.create_connection(bridge.server_address, timeout=3) as client:
            client.sendall(b"CONNECT web.telegram.org:443 HTTP/1.1\r\n\r\n")
            assert b"502 Proxy unavailable" in client.recv(4096)
        assert len(requests) == 1
    finally:
        upstream.shutdown()
        upstream.server_close()
        bridge.shutdown()
        bridge.server_close()
        thread.join(3)
        worker.join(3)


def test_upstream_failure_never_attempts_direct_destination(monkeypatch):
    calls = []

    def unavailable(address, **kwargs):
        calls.append(address)
        raise OSError("private diagnostic")

    monkeypatch.setattr(socket, "create_connection", unavailable)
    with pytest.raises(OSError):
        connect_upstream(configuration({"server": "http://gateway:3128"}), "web.telegram.org", 443)
    assert calls == [("gateway", 3128)]
