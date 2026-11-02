import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from urllib.request import Request, urlopen
import webbrowser

QUICK_URL = re.compile(r"https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com(?=$|[\s\"'|])")
TOOLS = {
    "cloudflared": {
        "version": "2026.10.7",
        "url": "https://github.com/cloudflare/cloudflared/releases/download/2026.10.7/cloudflared-linux-{arch}",
        "amd64": "1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872",
        "arm64": "3df43aedc9ff291d1735b5cb576cb97e0b157488796db2e32b28aecabb445775",
    },
    "caddy": {
        "version": "2.11.7",
        "url": "https://github.com/caddyserver/caddy/releases/download/v2.11.7/caddy_2.11.7_linux_{arch}.tar.gz",
        "amd64": "727b91701a392de6ebc5027509f548bf39979e5216340d0faed8fa5e69c84f8b",
        "arm64": "d8fc6d179a5d283028a472a5618564f6ad8a86fed513e64f032b3b0b7cc45e42",
    },
}


def atomic(path, text, mode=0o600):
    if path.is_symlink():
        raise ValueError(f"Refusing a linked file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text.encode())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def hostname(value):
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or "." not in value:
        raise ValueError("Enter a public hostname such as panel.example.org, without https:// or a path.")
    for label in value.split("."):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ValueError("Enter a hostname using letters, digits, dots and hyphens only.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Use a domain name for automatic HTTPS, not an IP address.")
    if value.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".example")):
        raise ValueError("Use a public DNS name for automatic HTTPS.")
    return value


def check_port(port, host="127.0.0.1"):
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    with socket.socket() as connection:
        try:
            connection.bind((host, port))
        except OSError as exc:
            raise ValueError(f"Port {port} is already in use or unavailable. Nothing was stopped.") from exc


def command(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def systemctl(config, *args, **kwargs):
    return command(["systemctl", *([] if config["system"] else ["--user"]), *args], **kwargs)


def service_name(root):
    return "tgwitness-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]


def unit_quote(value):
    # systemd specifiers and environment expansion apply even inside quotes.
    if any(c in str(value) for c in "\r\n\0"):
        raise ValueError("A service path contains a control character.")
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def unit_text(root, config, python):
    hardening = ""
    if config["system"]:
        hardening = ("DynamicUser=yes\nStateDirectory=" + config["service"] + "\nStateDirectoryMode=0700\n"
                     "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n")
        if config["mode"] == "domain":
            hardening += "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        else:
            hardening += "CapabilityBoundingSet=\n"
    argv = [python, "-I", "-m", "tgwitness.panelctl", "--root", root, "_serve"]
    return ("# TgWitness managed panel service v1\n[Unit]\nDescription=TgWitness panel and collection\n"
            "After=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\n"
            "ExecStart=" + " ".join(unit_quote(v) for v in argv) + "\n"
            "Restart=on-failure\nRestartSec=5\nTimeoutStopSec=45\nKillMode=control-group\n"
            "UMask=0077\nNoNewPrivileges=yes\n" + hardening +
            "\n[Install]\nWantedBy=" + ("multi-user.target" if config["system"] else "default.target") + "\n")


def fetch_tool(root, name):
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if not arch:
        raise ValueError("Public panel setup supports Linux x64 and ARM64.")
    spec = TOOLS[name]
    folder = root / "tools" / (name + "-" + spec["version"] + "-" + arch)
    folder.mkdir(mode=0o755, parents=True, exist_ok=True)
    binary = folder / name
    receipt = folder / "sha256"
    if binary.is_file() and receipt.is_file() and not binary.is_symlink():
        if hashlib.sha256(binary.read_bytes()).hexdigest() == receipt.read_text().strip():
            return binary
        raise ValueError(f"The installed {name} binary has changed. Refusing to run it.")
    print(f"Preparing {name} {spec['version']} (SHA-256 checked)...", flush=True)
    with tempfile.TemporaryDirectory(dir=folder) as scratch:
        archive = Path(scratch) / "download"
        digest = hashlib.sha256()
        with urlopen(spec["url"].format(arch=arch), timeout=30) as response, archive.open("wb") as output:
            if not response.url.startswith("https://"):
                raise ValueError("Refusing a download redirected away from HTTPS.")
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 160 * 1024 * 1024:
                    raise ValueError("Tool download exceeds its size limit.")
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != spec[arch]:
            raise ValueError(f"{name} checksum does not match. The download was not executed.")
        if name == "caddy":
            with tarfile.open(archive) as bundle:
                member = bundle.getmember("caddy")
                if not member.isfile() or member.size > 160 * 1024 * 1024:
                    raise ValueError("Invalid Caddy archive.")
                with bundle.extractfile(member) as source, binary.open("xb") as target:
                    shutil.copyfileobj(source, target)
        else:
            os.replace(archive, binary)
        binary.chmod(0o755)
        atomic(receipt, hashlib.sha256(binary.read_bytes()).hexdigest() + "\n", 0o644)
    return binary


def read_config(root):
    data = json.loads((root / "panel.json").read_text())
    if data.get("schema") != "tgwitness-panel-v1" or data.get("service") != service_name(root):
        raise ValueError("Unrecognized panel configuration. Existing data was left unchanged.")
    if data["mode"] not in ("local", "quick", "domain") or not 1024 <= data["port"] <= 65535:
        raise ValueError("Invalid panel configuration.")
    if data["mode"] == "domain":
        hostname(data["domain"])
    return data


def prepare_code(root):
    root.chmod(0o755)
    for name in ("versions", "tools"):
        folder = root / name
        folder.chmod(0o755)
        for entry in folder.rglob("*"):
            if entry.is_symlink():
                continue
            entry.chmod(0o755 if entry.is_dir() or entry.stat().st_mode & 0o111 else 0o644)


def refresh_unit(root, config, first=False):
    unit_dir = Path("/etc/systemd/system") if config["system"] else Path.home() / ".config/systemd/user"
    unit = unit_dir / (config["service"] + ".service")
    if unit.exists():
        if first or not unit.read_text().startswith("# TgWitness managed panel service v1\n"):
            raise ValueError(f"A service already occupies {unit}. Nothing was replaced.")
    if config["system"]:
        prepare_code(root)
    atomic(unit, unit_text(root, config, sys.executable), 0o644)
    systemctl(config, "daemon-reload")


def open_terminal():
    try:
        return open("CONIN$" if os.name == "nt" else "/dev/tty", "r", encoding="utf-8")
    except OSError:
        return None


def choose(stream, prompt, choices=None, default=None):
    while True:
        print(prompt, end=" ", flush=True)
        line = stream.readline()
        if not line:
            raise ValueError("Setup cancelled. Nothing was exposed. Run tgwitness setup to try again.")
        result = line.strip() or default
        if result is not None and (choices is None or result in choices):
            return result
        print("Choose one of the listed options.")


def setup(root, mode=None, domain=None, port=8787):
    if (root / "panel.json").exists():
        print("A panel is already configured. Your access settings and data were kept.")
        show(root, credentials=True)
        print("After installing a new program version, apply it with: tgwitness restart")
        return
    linux = sys.platform == "linux" and Path("/run/systemd/system").exists()
    if mode is None:
        terminal = open_terminal()
        if terminal is None:
            print("Installed. Run tgwitness setup from a terminal to choose how to open the panel.")
            return
        with terminal:
            print("\nWhere would you like to open your panel?\n"
                  "  1  On this computer only\n" +
                  ("  2  HTTPS link through trycloudflare.com (no domain needed)\n"
                   "  3  My own domain with automatic HTTPS\n" if linux else "") +
                  "  4  Install only; decide later\n")
            selection = choose(terminal, "Choose [1-4]:" if linux else "Choose [1 or 4]:",
                               {"1", "2", "3", "4"} if linux else {"1", "4"})
            if selection == "4":
                print("Installed. Start setup later with: tgwitness setup")
                return
            mode = {"1": "local", "2": "quick", "3": "domain"}[selection]
            if mode == "quick":
                print("Your files stay on this machine. Panel traffic passes through Cloudflare.\n"
                      "This is a temporary address: after a tunnel restart, run tgwitness open for the new link.")
            if mode == "domain":
                print("Point your domain's DNS at this server and allow inbound TCP 80 and 443.")
                domain = choose(terminal, "Panel domain (for example panel.example.org):")
    if mode not in ("local", "quick", "domain"):
        raise ValueError("Choose local, quick or domain access.")
    if not linux:
        if mode != "local":
            raise ValueError("Automatic public access currently needs Linux with systemd. Choose local on this computer.")
        from .__main__ import main, open_when_ready
        check_port(port)
        data = root / "data" / "live"
        threading.Thread(target=open_when_ready, daemon=True,
                         args=(f"http://127.0.0.1:{port}", "127.0.0.1", port, data / "panel-token.txt")).start()
        sys.argv = ["tgwitness", "--data-dir", str(data), "--port", str(port), "--no-browser"]
        main()
        return
    is_system = os.geteuid() == 0
    if is_system and any(root.is_relative_to(Path(p)) for p in ("/root", "/home", "/tmp", "/var/tmp")):
        raise ValueError("A system service needs an installation outside home and temporary directories. Install under /opt/tgwitness.")
    if mode == "domain" and not is_system:
        raise ValueError("Automatic HTTPS on ports 80/443 needs a system installation. Run the installer as root, or choose the HTTPS link.")
    if not 1024 <= port <= 65535:
        raise ValueError("Choose a panel port between 1024 and 65535.")
    check_port(port)
    if mode == "domain":
        domain = hostname(domain or "")
        check_port(80, "0.0.0.0")
        check_port(443, "0.0.0.0")
        try:
            socket.getaddrinfo(domain, 443)
        except OSError as exc:
            raise ValueError("The domain does not resolve. Set its DNS first or choose the temporary HTTPS link.") from exc
    service = service_name(root)
    config = {"schema": "tgwitness-panel-v1", "mode": mode, "domain": domain, "port": port,
              "system": is_system, "service": service,
              "data": str(Path("/var/lib") / service if is_system else root / "data" / "live")}
    systemctl(config, "show-environment", stdout=subprocess.DEVNULL)
    if mode != "local":
        config["bridge"] = str(fetch_tool(root, "cloudflared" if mode == "quick" else "caddy"))
    refresh_unit(root, config, first=True)
    atomic(root / "panel.json", json.dumps(config, indent=2) + "\n", 0o644)
    systemctl(config, "enable", "--now", service)
    print("Starting your panel...", flush=True)
    show(root, credentials=True, wait=120)
    if not is_system:
        print("Starts at login. To keep it running after sign-out and start at boot, an administrator can enable user lingering.")


def reachable(url, expected=None):
    try:
        with urlopen(Request(url, headers={"User-Agent": "TgWitness-Setup/1"}), timeout=4) as response:
            return response.status == 200 and (expected is None or response.read(128) == expected.encode())
    except (OSError, ValueError):
        return False


def show(root, credentials=False, wait=0):
    config = read_config(root)
    data = Path(config["data"])
    deadline = time.monotonic() + wait
    while True:
        active = subprocess.run(["systemctl", *([] if config["system"] else ["--user"]),
                                 "is-active", "--quiet", config["service"]]).returncode == 0
        try:
            state = json.loads((data / "panel-address.json").read_text()) if active else {}
        except (FileNotFoundError, json.JSONDecodeError):
            state = {}
        url = state.get("url")
        identity = state.get("id", "")
        ready = (active and url and re.fullmatch(r"[0-9a-f]{64}", identity)
                 and reachable(url.rstrip("/") + "/_tgwitness/ready", identity))
        if ready or time.monotonic() >= deadline:
            break
        time.sleep(1)
    if not ready:
        print("Panel is starting or needs attention. Run: tgwitness logs\nThen: tgwitness open")
        if url:
            print("Configured address (this panel is not yet confirmed there): " + url)
        if config["mode"] == "domain":
            print("Check that DNS points to this server and ports 80/443 are reachable for HTTPS.")
        if wait:
            raise ValueError("Panel readiness was not confirmed. Your installation and data were kept.")
        return
    print("\nYour panel is ready\n\n  Open: " + url)
    if credentials:
        print("  Access key: " + (data / "panel-token.txt").read_text().strip())
    print("\nData: " + str(data) + "\n\nManage: tgwitness status | open | restart | stop | logs\n"
          "Use the access key in the panel. Telegram sign-in is the next step in your browser.")
    if config["mode"] == "quick":
        print("Public tunnel is off. The panel is local; collection can keep running." if state.get("tunnel_enabled") is False else
              "Temporary HTTPS link. After a tunnel restart: tgwitness open")
    if config["mode"] == "local" and os.environ.get("SSH_CONNECTION"):
        print("Local mode is reachable on the server only. Public access was not enabled.")
    elif credentials and not os.environ.get("SSH_CONNECTION"):
        webbrowser.open(url)


def bridge_command(config, data):
    origin = "http://127.0.0.1:" + str(config["port"])
    if config["mode"] == "quick":
        empty = data / "tunnel-config.yml"
        atomic(empty, "{}\n")
        return [config["bridge"], "tunnel", "--config", str(empty), "--no-autoupdate",
                "--metrics", "127.0.0.1:0", "--url", origin]
    caddy = data / "Caddyfile"
    atomic(caddy, hostname(config["domain"]) + " {\n  reverse_proxy " + origin + "\n}\n")
    return [config["bridge"], "run", "--config", str(caddy), "--adapter", "caddyfile"]


def tunnel_control(root):
    path = root / "tunnel.json"
    if not path.exists():
        return {"enabled": True, "revision": ""}
    data = json.loads(path.read_text())
    if type(data.get("enabled")) is not bool or not re.fullmatch(r"[0-9a-f]{32}", data.get("revision", "")):
        raise ValueError("Invalid tunnel.json. Public access was not enabled.")
    return data


def stop_child(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def tunnel(root, action):
    config = read_config(root)
    if config["mode"] != "quick":
        raise ValueError("Tunnel commands apply to a managed trycloudflare.com installation.")
    if action == "status":
        print("Tunnel: " + ("enabled" if tunnel_control(root)["enabled"] else "off"))
        return
    control = {"enabled": action != "off", "revision": secrets.token_hex(16)}
    atomic(root / "tunnel.json", json.dumps(control) + "\n", 0o644)
    active = subprocess.run(["systemctl", *([] if config["system"] else ["--user"]),
                             "is-active", "--quiet", config["service"]]).returncode == 0
    if not active:
        print("Tunnel preference saved. The panel is stopped; start it with: tgwitness start")
        return
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            state = json.loads((Path(config["data"]) / "panel-address.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            state = {}
        if state.get("tunnel_revision") == control["revision"] and state.get("url"):
            print("Tunnel " + ("enabled. Current link: " + state["url"] if control["enabled"] else
                              "closed. Collection and the local panel keep running."))
            return
        time.sleep(.5)
    raise ValueError("Tunnel change is saved but not yet confirmed. Run tgwitness status and tgwitness logs.")


def token_rotate(root, port=8787):
    config = read_config(root) if (root / "panel.json").exists() else {"data": str(root / "data" / "live"), "port": port}
    token = (Path(config["data"]) / "panel-token.txt").read_text().strip()
    request = Request(f"http://127.0.0.1:{config['port']}/api/access/token", data=b"{}",
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=15) as response:
        result = json.load(response)
    logout = Request(f"http://127.0.0.1:{config['port']}/api/access/logout", data=b"{}",
                     headers={"Authorization": "Bearer " + result["session"], "Content-Type": "application/json"}, method="POST")
    with urlopen(logout, timeout=15):
        pass
    print("Administrator key replaced. All previous browser sessions ended.\n  Access key: " + result["token"])


def guide(root, print_text=False, write_only=False):
    from .operator_guide import write
    path = root / "START-HERE.html"
    if write_only or not path.is_file() or not (root / "START-HERE.txt").is_file():
        path = write(root)
    if write_only:
        return
    if print_text or os.environ.get("SSH_CONNECTION"):
        print((root / "START-HERE.txt").read_text(encoding="utf-8").replace(" → ", " > "))
    else:
        print("Operator guide: " + str(path))
        if sys.stdout.isatty():
            webbrowser.open(path.as_uri())


def serve(root):
    config = read_config(root)
    data = Path(config["data"])
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    address = data / "panel-address.json"
    atomic(address, "{}\n")
    installation_id = secrets.token_hex(32)
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    env = dict(os.environ, TGWITNESS_NO_BROWSER="1", TGWITNESS_INSTALLATION_ID=installation_id,
               XDG_DATA_HOME=str(data / "service-data"),
               XDG_CONFIG_HOME=str(data / "service-config"))
    env["TGWITNESS_TRUSTED_PROXIES"] = "127.0.0.1/32,::1/128" if config["mode"] != "local" else ""
    env["TGWITNESS_PROXY_HEADER"] = "cf-connecting-ip" if config["mode"] == "quick" else "x-forwarded-for"
    app = subprocess.Popen([sys.executable, "-I", "-m", "tgwitness", "--host", "127.0.0.1", "--port",
                            str(config["port"]), "--data-dir", str(data), "--no-browser"], env=env)
    bridge, last_control = None, None
    try:
        origin = "http://127.0.0.1:" + str(config["port"])
        deadline = time.monotonic() + 90
        while not reachable(origin + "/_tgwitness/ready", installation_id):
            if app.poll() is not None or stopping.wait(0.5) or time.monotonic() > deadline:
                raise RuntimeError("The local panel did not start. See tgwitness logs.")
        if config["mode"] != "quick":
            atomic(address, json.dumps({"url": origin if config["mode"] == "local" else "https://" + config["domain"], "id": installation_id}))

        def read_bridge_output(process, revision):
            for line in process.stdout:
                print(line.rstrip(), flush=True)
                match = QUICK_URL.search(line)
                if match and bridge is process and not stopping.is_set():
                    atomic(address, json.dumps({"url": match.group(0), "id": installation_id,
                                                "tunnel_revision": revision, "tunnel_enabled": True}))

        while not stopping.wait(0.5):
            if app.poll() is not None:
                raise RuntimeError("The panel exited; systemd will restart the service.")
            control = {"enabled": config["mode"] != "local", "revision": ""}
            if config["mode"] == "quick":
                try:
                    control = tunnel_control(root)
                except (OSError, ValueError):
                    control = {"enabled": False, "revision": "invalid"}
                if control != last_control:
                    old, bridge = bridge, None
                    stop_child(old)
                    atomic(address, json.dumps({"url": None if control["enabled"] else origin,
                                                "id": installation_id, "tunnel_revision": control["revision"],
                                                "tunnel_enabled": control["enabled"]}))
                    last_control = control
            if control["enabled"] and (bridge is None or bridge.poll() is not None):
                if bridge is not None:
                    atomic(address, "{}\n")
                    if stopping.wait(5):
                        break
                bridge = subprocess.Popen(bridge_command(config, data), env=env, stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, text=True, errors="replace")
                if config["mode"] == "domain":
                    atomic(address, json.dumps({"url": "https://" + config["domain"], "id": installation_id}))
                threading.Thread(target=read_bridge_output, args=(bridge, control["revision"]), daemon=True).start()
    finally:
        stopping.set()
        atomic(address, "{}\n")
        for child in (bridge, app):
            stop_child(child)


def main():
    parser = argparse.ArgumentParser(description="Install once. Open and manage your TgWitness panel.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("action", nargs="?", default="open", choices=["setup", "open", "status", "start", "stop", "restart", "logs", "doctor", "guide", "paths", "token", "tunnel", "_serve"])
    parser.add_argument("operation", nargs="?", choices=["rotate", "off", "on", "restart", "status"])
    parser.add_argument("--print", dest="print_text", action="store_true")
    parser.add_argument("--write-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--mode", choices=["local", "quick", "domain"])
    parser.add_argument("--domain")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if not (root / ".tgwitness-installer").is_file() and not (root / ".tgwitness-installer.json").is_file():
            if not (root / "bin" / "tgwitness.cmd").is_file():
                raise ValueError("Use this command from a managed TgWitness installation.")
        if args.action == "guide":
            guide(root, args.print_text, args.write_only)
        elif args.action == "paths":
            config = read_config(root) if (root / "panel.json").exists() else {"data": str(root / "data" / "live")}
            print("Program: " + str(root) + "\nData: " + config["data"] + "\nGuide: " + str(root / "START-HERE.html"))
        elif args.action == "token":
            if args.operation != "rotate":
                raise ValueError("Use: tgwitness token rotate (the panel must be running).")
            token_rotate(root, args.port)
        elif args.action == "tunnel":
            if args.operation not in ("on", "off", "restart", "status"):
                raise ValueError("Use: tgwitness tunnel on | off | restart | status")
            tunnel(root, args.operation)
        elif args.action == "setup" or (args.action == "open" and not (root / "panel.json").exists()):
            setup(root, args.mode, args.domain, args.port)
        elif args.action == "_serve":
            serve(root)
        elif args.action in ("open", "status"):
            show(root, credentials=args.action == "open", wait=30 if args.action == "open" else 0)
        elif args.action in ("start", "stop", "restart"):
            config = read_config(root)
            if args.action != "stop":
                refresh_unit(root, config)
            systemctl(config, args.action, config["service"])
            if args.action != "stop":
                show(root, wait=90)
            else:
                print("Panel stopped. Your data is kept. Start again: tgwitness start")
        elif args.action == "logs":
            config = read_config(root)
            command(["journalctl", *([] if config["system"] else ["--user"]), "-u", config["service"], "-n", "80", "--no-pager"])
        elif args.action == "doctor":
            config = read_config(root)
            command([sys.executable, "-I", "-m", "tgwitness", "--check", "--data-dir", config["data"]])
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print("TgWitness: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
