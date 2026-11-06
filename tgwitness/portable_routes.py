import asyncio
import base64
import configparser
import hashlib
import io
import ipaddress
import os
import platform
import re
import secrets
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from . import netclient
from .network import NetworkConfig
from .security import owner_only, private_write


VERSIONS = {"wgcf": "2.3.1", "wireproxy": "1.1.3"}
HASHES = {
    "wgcf": {
        "linux_amd64": "4fb7a136aa470ece11d17949c7db07b040ec9c604742dc8680bcf1889f85d0c8",
        "linux_arm64": "710ab2d8ac145d81a4cf0c11bdb0e05914f77ae2a45f67b87e718d84b4cb7301",
        "darwin_amd64": "de295a28dd7503cd779c9afa2bf2e59435107bace94bdc0b57b66d8c9d9408ad",
        "darwin_arm64": "45be8d5ea91fd0b938a1775fd3e0b29a33b756b6cc67a0a9f305bcf86ff608c2",
        "windows_amd64": "e222fd9443d7cb3264d825a3e86967797fc9c938507c5d93e3cc21e4aed11dcc",
    },
    "wireproxy": {
        "linux_amd64": "e88c1d090740373fc606c1bafd81d9a5eadc642cce5667616e20e9d7a444f51c",
        "linux_arm64": "370e00bd2167960d1ecd1c3c1439715bbaa94a0a110a2040468670c9af6021b6",
        "darwin_amd64": "5d89742a0f381d9508d3ad828a0d300dceee24fa49015427eaff42a23f7a50bd",
        "darwin_arm64": "28d34342c48c309b628d9c06ab4efc05b82fba49821f360605c02139c02547a5",
        "windows_amd64": "bce041ea9fe0f8a3351301dcbe29cdf6a523bb25cf9c62f17ebb5699a8051d0f",
    },
}
MAX_DOWNLOAD = 32 * 1024 * 1024
CREATE_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def check_asset_url(url):
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.hostname not in {
            "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
            or parts.username or parts.password or parts.port not in (None, 443)):
        raise ValueError("Tunnel helper download redirected outside the approved release hosts.")


class ReleaseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_asset_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_asset(url):
    check_asset_url(url)
    opener = build_opener(ProxyHandler({}), ReleaseRedirect())
    content, started = bytearray(), time.monotonic()
    with opener.open(Request(url, headers={"User-Agent": "TgWitness portable setup"}), timeout=20) as response:
        while True:
            if time.monotonic() - started > 120:
                raise TimeoutError("Tunnel helper download timed out")
            chunk = response.read(64 * 1024)
            if not chunk:
                return bytes(content)
            content.extend(chunk)
            if len(content) > MAX_DOWNLOAD:
                raise ValueError("Tunnel helper download is too large.")


def target_platform():
    system = platform.system().lower()
    machine = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(
        platform.machine().lower(), "unsupported")
    return system + "_" + machine


def asset(tool, target):
    if target not in HASHES[tool]:
        raise ValueError("Portable tunnels are unavailable on this platform. Use an existing SOCKS5 proxy.")
    version = VERSIONS[tool]
    name = (f"wgcf_{version}_{target}" + (".exe" if target.startswith("windows_") else "")
            if tool == "wgcf" else f"wireproxy_{target}.tar.gz")
    repo = "ViRb3/wgcf" if tool == "wgcf" else "windtf/wireproxy"
    return f"https://github.com/{repo}/releases/download/v{version}/{name}", HASHES[tool][target]


def binary_data(tool, content, expected, windows):
    if len(content) > MAX_DOWNLOAD or hashlib.sha256(content).hexdigest() != expected:
        raise ValueError("Tunnel helper checksum mismatch. Nothing was executed.")
    if tool == "wgcf":
        return content
    name = "wireproxy.exe" if windows else "wireproxy"
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        matches = [m for m in archive.getmembers() if m.name in (name, "./" + name)]
        if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= MAX_DOWNLOAD:
            raise ValueError("Invalid tunnel helper archive.")
        return archive.extractfile(matches[0]).read(MAX_DOWNLOAD + 1)


async def install_helper(root, tool, allow_download=False):
    target = target_platform()
    url, expected = asset(tool, target)
    root.mkdir(parents=True, exist_ok=True)
    cache = root / (tool + "-" + VERSIONS[tool] + "-" + target + ".download")
    if not cache.exists():
        if not allow_download:
            raise ValueError("Prepare the tunnel helpers in Connection before starting this route.")
        content = await asyncio.to_thread(fetch_asset, url)
        binary_data(tool, content, expected, target.startswith("windows_"))
        private_write(cache, content)
    if cache.stat().st_size > MAX_DOWNLOAD:
        raise ValueError("Tunnel helper download is too large.")
    executable = binary_data(tool, cache.read_bytes(), expected, target.startswith("windows_"))
    path = root / (tool + "-" + VERSIONS[tool] + (".exe" if os.name == "nt" else ""))
    if not path.exists() or path.stat().st_size != len(executable) or path.read_bytes() != executable:
        private_write(path, executable)
    if os.name != "nt":
        path.chmod(0o700)
    return path.resolve()


def wireguard_profile(text):
    if not isinstance(text, str) or not 1 <= len(text) <= 16384:
        raise ValueError("Supply a WireGuard profile of at most 16 KB.")
    parser = configparser.ConfigParser(interpolation=None, strict=True, empty_lines_in_values=False)
    parser.optionxform = str
    try:
        parser.read_string(text)
        if parser.defaults() or set(parser.sections()) != {"Interface", "Peer"}:
            raise ValueError
        allowed = {"Interface": {"PrivateKey", "Address", "DNS", "MTU"},
                   "Peer": {"PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"}}
        for section, keys in allowed.items():
            if set(parser[section]) - keys:
                raise ValueError
            for value in parser[section].values():
                if not value or any(c in value for c in "\r\n$;\x00"):
                    raise ValueError
        interface, peer = dict(parser["Interface"]), dict(parser["Peer"])
        for value in (interface["PrivateKey"], peer["PublicKey"], *([peer["PresharedKey"]] if "PresharedKey" in peer else [])):
            if len(base64.b64decode(value, validate=True)) != 32:
                raise ValueError
        interface["Address"] = ", ".join(str(ipaddress.ip_interface(p.strip())) for p in interface["Address"].split(","))
        interface["DNS"] = ", ".join(str(ipaddress.ip_address(p.strip())) for p in interface.get("DNS", "1.1.1.1").split(","))
        interface["MTU"] = str(int(interface.get("MTU", "1280")))
        if not 576 <= int(interface["MTU"]) <= 9000:
            raise ValueError
        if set(p.strip() for p in peer["AllowedIPs"].split(",")) != {"0.0.0.0/0", "::/0"}:
            raise ValueError
        host, port = peer["Endpoint"].rsplit(":", 1)
        endpoint = NetworkConfig(kind="socks5", host=host.strip("[]"), port=int(port))
        keepalive = int(peer.get("PersistentKeepalive", "25"))
        if not 0 <= keepalive <= 65535:
            raise ValueError
        peer["PersistentKeepalive"] = str(keepalive)
        return {"interface": interface, "peer": peer, "host": endpoint.host, "port": endpoint.port}
    except (ValueError, KeyError, configparser.Error):
        raise ValueError("Invalid WireGuard profile. Use one Interface and one Peer, full IPv4/IPv6 routes, "
                         "and no scripts, includes or extra listeners.") from None


async def runtime_config(profile, route):
    addresses = await netclient.resolve(profile["host"], profile["port"])
    netclient.refuse_internal(profile["host"], addresses)
    if not addresses:
        raise ValueError("The VPN endpoint could not be resolved.")
    address = addresses[0]
    endpoint = ("[" + address + "]" if ":" in address else address) + ":" + str(profile["port"])
    peer = {**profile["peer"], "Endpoint": endpoint}
    sections = {"Interface": profile["interface"], "Peer": peer,
                "Socks5": {"BindAddress": f"127.0.0.1:{route.port}", "Username": route.username, "Password": route.password}}
    return "\n".join("[" + section + "]\n" + "\n".join(k + " = " + v for k, v in values.items())
                     for section, values in sections.items()) + "\n"


async def run_helper(executable, args, cwd, timeout=90):
    process = await asyncio.create_subprocess_exec(str(executable), *args, cwd=str(cwd),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=CREATE_FLAGS)
    try:
        if await asyncio.wait_for(process.wait(), timeout) != 0:
            raise ValueError("Tunnel helper failed. Check network access or import an existing WireGuard profile.")
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


class PortableRoutes:
    def __init__(self, collector):
        self.collector, self.vault = collector, collector.vault
        self.root = self.vault.root / "portable-routes"
        self.processes = {}
        self.configs = {}
        self.lock = asyncio.Lock()

    def selected(self):
        saved = self.vault.read("portable_route")
        if saved and saved.get("network"):
            normalized = NetworkConfig.model_validate(saved["network"]).model_dump()
            if normalized == self.collector.network_config().model_dump():
                return {**saved, "network": normalized}
        return None

    async def prepare(self, mode, text, consent, progress):
        self.root.mkdir(parents=True, exist_ok=True)
        owner_only(self.root)
        progress("Checking tunnel helpers")
        wireproxy = await install_helper(self.root / "bin", "wireproxy", consent)
        if mode == "warp":
            saved = self.vault.read("warp_profile")
            if saved:
                text = saved["profile"]
            else:
                if not consent:
                    raise ValueError("Accept the setup notice before registering a WARP device.")
                wgcf = await install_helper(self.root / "bin", "wgcf", True)
                progress("Registering WARP on this machine")
                with tempfile.TemporaryDirectory(prefix="registration-", dir=self.root) as folder:
                    path = Path(folder)
                    owner_only(path)
                    account = self.vault.read("warp_account")
                    if account:
                        private_write(path / "wgcf-account.toml", account["toml"].encode())
                    else:
                        try:
                            await run_helper(wgcf, ["register", "--accept-tos"], path)
                        finally:
                            account_file = path / "wgcf-account.toml"
                            if account_file.is_file() and account_file.stat().st_size <= 16384:
                                self.vault.save("warp_account", {"toml": account_file.read_text()})
                    await run_helper(wgcf, ["generate", "--keepalive=25"], path)
                    text = (path / "wgcf-profile.conf").read_text()
                    wireguard_profile(text)
                    self.vault.save("warp_profile", {"profile": text})
        profile = wireguard_profile(text)
        async with self.lock:
            selected = self.selected()
            if selected and wireguard_profile(selected["profile"]) == profile and selected["mode"] == mode:
                saved = {k: v for k, v in selected.items() if k != "paused"}
                await self._start(saved, executable=wireproxy, profile=profile)
                return saved
            for identifier, known in self.configs.items():
                process = self.processes.get(identifier)
                previous = wireguard_profile(known["profile"])
                if process and process.returncode is None and previous["interface"]["PrivateKey"] == profile["interface"]["PrivateKey"]:
                    raise ValueError("A tunnel using this WireGuard key is already running. Stop it before changing its profile.")
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            network = NetworkConfig(kind="socks5", host="127.0.0.1", port=port, local_proxy=True,
                                    username=secrets.token_hex(16), password=secrets.token_hex(24))
            saved = {"id": secrets.token_hex(16), "mode": mode, "profile": text, "network": network.model_dump()}
            progress("Starting the local tunnel")
            await self._start(saved, executable=wireproxy, profile=profile)
            return saved

    async def start(self, saved, executable=None, profile=None):
        async with self.lock:
            await self._start(saved, executable, profile)

    async def _start(self, saved, executable=None, profile=None):
        identifier = saved["id"]
        if not re.fullmatch("[a-f0-9]{32}", identifier):
            raise ValueError("Invalid local tunnel identifier.")
        current = self.processes.get(identifier)
        if current and current.returncode is None:
            return
        profile = profile or wireguard_profile(saved["profile"])
        for other, known in self.configs.items():
            process = self.processes.get(other)
            if (other != identifier and process and process.returncode is None
                    and wireguard_profile(known["profile"])["interface"]["PrivateKey"] == profile["interface"]["PrivateKey"]):
                raise ValueError("A tunnel using this WireGuard key is already running. Stop it before changing its profile.")
        executable = executable or await install_helper(self.root / "bin", "wireproxy")
        route = NetworkConfig.model_validate(saved["network"])
        config = await runtime_config(profile, route)
        path = self.root / (identifier + ".conf")
        private_write(path, config.encode())
        try:
            await run_helper(executable, ["-n", "-c", str(path.resolve())], self.root, timeout=10)
            worker = Path(__file__).with_name("route_worker.py").resolve()
            process = await asyncio.create_subprocess_exec(sys.executable, str(worker), str(executable),
                "-s", "-c", str(path.resolve()), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, creationflags=CREATE_FLAGS)
            self.processes[identifier] = process
            self.configs[identifier] = saved
            for _ in range(50):
                if process.returncode is not None:
                    break
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", route.port), 1)
                    try:
                        writer.write(b"\x05\x01\x02")
                        await writer.drain()
                        if await asyncio.wait_for(reader.readexactly(2), 1) != b"\x05\x02":
                            raise ValueError("The local tunnel port is occupied by another service.")
                        user, password = route.username.encode(), route.password.encode()
                        writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
                        await writer.drain()
                        if await asyncio.wait_for(reader.readexactly(2), 1) != b"\x01\x00":
                            raise ValueError("The local tunnel did not accept its private credentials.")
                        return
                    finally:
                        writer.close()
                        with suppress(OSError):
                            await writer.wait_closed()
                except (OSError, TimeoutError, asyncio.IncompleteReadError):
                    await asyncio.sleep(.1)
            raise ValueError("The local tunnel could not start. Its port may already be in use.")
        except BaseException:
            await self._stop(identifier)
            raise

    async def restore(self):
        saved = self.selected()
        if saved and not saved.get("paused"):
            await self.start(saved)

    async def stop(self, identifier):
        async with self.lock:
            await self._stop(identifier)

    async def _stop(self, identifier):
        process = self.processes.get(identifier)
        if process and process.returncode is None:
            process.stdin.close()
            await asyncio.wait_for(process.wait(), 10)
        self.processes.pop(identifier, None)
        self.configs.pop(identifier, None)
        (self.root / (identifier + ".conf")).unlink(missing_ok=True)

    async def close(self):
        for identifier in list(self.processes):
            await self.stop(identifier)
