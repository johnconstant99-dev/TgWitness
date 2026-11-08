import hashlib
import ipaddress
import os
import re
import shutil
import signal
import socket
import subprocess
from pathlib import Path

from .format import decode, digest


def connector_config(raw):
    if not isinstance(raw, dict) or not raw:
        raise ValueError("Configure at least one operator-selected connector")
    result = {}
    for name, value in raw.items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", name) or not isinstance(value, dict):
            raise ValueError("Invalid connector")
        if set(value) != {"label", "mode", "protocol", "host", "port"}:
            raise ValueError("Connector requires label, mode, protocol, host and port; no credentials")
        if value["mode"] not in {"proxy", "warp_proxy", "warp_witness"}:
            raise ValueError("Unknown connector mode")
        if value["protocol"] not in {"socks5", "http", "mtproxy"}:
            raise ValueError("Unknown connector protocol")
        address = ipaddress.ip_address(value["host"])
        if address.version != 4 or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError("Use the connector's fixed IPv4 address outside the client namespace")
        if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
            raise ValueError("Invalid connector port")
        if not isinstance(value["label"], str) or not 1 <= len(value["label"]) <= 120:
            raise ValueError("Invalid connector label")
        if value["mode"].startswith("warp") and value["protocol"] == "mtproxy":
            raise ValueError("WARP connectors require a SOCKS5 or HTTP gateway")
        result[name] = value.copy()
    return result


class LinuxClient:
    def __init__(self, settings):
        self.settings = settings
        self.process = None
        self.expected_executable = None
        self.window = None
        self.egress_ip = None
        self.env = {**os.environ, "DISPLAY": settings.get("display", ":99")}

    def command(self, args, **kwargs):
        return subprocess.run(args, env=self.env, check=True, timeout=15,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **kwargs).stdout

    def route(self, connector):
        path = Path(self.settings.get("route_receipt", "/run/trusted-route.json"))
        if os.name != "posix" or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            raise ValueError("Missing protected network guard receipt")
        raw = path.read_bytes()
        receipt = decode(raw)
        if (receipt.get("policy") != "trusted-live-deny-direct-v1"
                or receipt.get("host") != connector["host"] or receipt.get("port") != connector["port"]
                or receipt.get("netns") != os.readlink("/proc/self/ns/net")):
            raise ValueError("Connector does not match the isolated network namespace")
        with socket.create_connection((connector["host"], connector["port"]), timeout=3):
            pass
        from .trusted_anchor import egress_probe
        egress = egress_probe(connector, self.egress_ip)
        self.egress_ip = egress.get("ip", self.egress_ip)
        return {"guard_receipt_sha256": digest(raw), "endpoint_reachable": True,
                "egress_sample": egress, "scope": "namespace policy, TCP reachability and sampled egress; not account identity"}

    def launch(self, choice, connector, profile):
        if os.name != "posix" or not Path("/proc").exists():
            raise ValueError("Live collection requires the isolated Linux runtime")
        for executable in ("xdotool", "ffmpeg"):
            if not shutil.which(executable):
                raise ValueError("Missing runtime dependency: " + executable)
        evidence = self.route(connector)
        binary = Path(self.settings.get("desktop_binary", "/opt/Telegram/Telegram") if choice.client == "desktop"
                      else self.settings.get("browser_binary", "/usr/bin/chromium")).resolve(strict=True)
        with binary.open("rb") as source:
            actual = hashlib.file_digest(source, "sha256").hexdigest()
        if choice.client == "desktop" and actual != self.settings.get("desktop_sha256"):
            raise ValueError("Official Desktop binary does not match the operator-pinned SHA-256")
        if choice.client == "web" and connector["protocol"] == "mtproxy":
            raise ValueError("Chromium does not support MTProxy")
        profile.mkdir(mode=0o700, parents=True, exist_ok=False)
        if choice.client == "desktop":
            args = [str(binary), "-workdir", str(profile), "-noupdate"]
        else:
            args = [str(binary), "--user-data-dir=" + str(profile), "--no-first-run", "--disable-background-networking",
                    "--disable-component-update", "--disable-sync", "--disable-extensions", "--disable-dev-shm-usage",
                    "--disable-features=Translate", "--password-store=basic", "--window-size=1280,720",
                    "--proxy-server=" + connector["protocol"] + "://" + connector["host"] + ":" + str(connector["port"]),
                    "--proxy-bypass-list=<-loopback>", "--host-resolver-rules=MAP * ~NOTFOUND",
                    "--app=https://web.telegram.org/k/"]
        self.process = subprocess.Popen(args, env=self.env, start_new_session=True,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.expected_executable = binary
        return {**evidence, "client_binary_sha256": actual, "official_origin": "https://web.telegram.org/" if choice.client == "web"
                else "operator-pinned official Desktop distribution", "build_measurement": "self-reported"}

    def frame(self):
        return self.command(["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "x11grab", "-video_size", "1280x720",
                             "-i", self.env["DISPLAY"], "-frames:v", "1", "-f", "image2pipe", "-vcodec", "png", "-"])

    def active_window(self):
        if self.process is None or self.process.poll() is not None:
            raise ValueError("Client exited")
        try:
            window = self.command(["xdotool", "getactivewindow"]).decode().strip()
            pid = int(self.command(["xdotool", "getwindowpid", window]).decode().strip())
        except subprocess.CalledProcessError:
            raise ValueError("Client window is not ready; wait and review the screen") from None
        if os.getpgid(pid) != self.process.pid:
            raise ValueError("Focus left the owned client")
        return window

    def arm(self):
        self.window = self.active_window()

    def scroll(self, direction):
        if self.active_window() != self.window:
            raise ValueError("Window changed; pause and review before continuing")
        self.command(["xdotool", "mousemove", "--window", self.window, "640", "360",
                      "click", "--clearmodifiers", "4" if direction == "up" else "5"])

    def setup_input(self, value):
        self.active_window()
        if value.action == "click":
            self.command(["xdotool", "mousemove", str(value.x), str(value.y), "click", "1"])
        elif value.action == "key":
            self.command(["xdotool", "key", "--clearmodifiers", value.key])
        else:
            self.command(["xdotool", "type", "--clearmodifiers", "--file", "-"], input=value.text.encode())

    def stop(self):
        process = self.process
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            except ProcessLookupError:
                pass
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process = None
