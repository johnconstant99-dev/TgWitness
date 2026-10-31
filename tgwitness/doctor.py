"""Local deployment checks. No Telegram authorization or external network requests."""
import base64
import importlib
import importlib.metadata
import json
import os
import platform
import shutil
import socket
import sys
import tempfile
from pathlib import Path


def inspect_environment(root, host="127.0.0.1", port=8787):
    root = Path(root).resolve()
    checks = []

    def add(name, status, detail):
        checks.append({"name": name, "status": status, "detail": detail})

    add("python", "pass" if sys.version_info >= (3, 11) else "fail", platform.python_version())
    for distribution, module in (("fastapi", "fastapi"), ("uvicorn", "uvicorn"),
                                  ("telethon", "telethon"), ("cryptography", "cryptography"),
                                  ("python-socks", "python_socks"), ("qrcode", "qrcode")):
        try:
            importlib.import_module(module)
            add(distribution, "pass", importlib.metadata.version(distribution))
        except Exception as exc:
            add(distribution, "fail", "Install/repair the project environment: " + type(exc).__name__)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        key.public_key().verify(key.sign(b"local readiness probe"), b"local readiness probe")
        add("signing_backend", "pass", "Ed25519 sign/verify available")
    except Exception as exc:
        add("signing_backend", "fail", type(exc).__name__)

    parent = root
    while not parent.exists() and parent.parent != parent:
        parent = parent.parent
    try:
        if not parent.is_dir():
            raise NotADirectoryError()
        with tempfile.TemporaryFile(prefix="tgwitness-check-", dir=parent) as probe:
            probe.write(b"write probe")
            probe.flush()
            os.fsync(probe.fileno())
        free = shutil.disk_usage(parent).free
        add("storage", "pass" if free >= 1024**3 else "warning",
            f"Write probe passed; {free // 1024**2} MiB free. Exports use the profile's private temporary directory.")
        if root.exists():
            from .security import owner_only_state
            limited, how = owner_only_state(root)
            add("data_permissions", "pass" if limited else "warning",
                "Only this account can open the data directory (" + how + ")" if limited else
                "Other local accounts may read the data directory and its keys (" + how + "). TgWitness limits it "
                "at startup where the file system allows; keep it on NTFS or a Unix file system.")
    except OSError as exc:
        add("storage", "fail", "Data path is not writable: " + type(exc).__name__)
    try:
        if not 1 <= port <= 65535:
            raise ValueError()
        # Binding only; no connection or external address lookup is performed.
        import ipaddress
        if host == "localhost":
            host = "127.0.0.1"
        address = ipaddress.ip_address(host)
        with socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET) as probe:
            probe.bind((host, port))
        add("listen_address", "pass", "Address and port available at check time")
    except (OSError, ValueError):
        add("listen_address", "fail", "Use a local IP and available port; a running instance may already own it.")

    external = os.environ.get("TGWITNESS_VAULT_KEY_FILE")
    marker = root / "vault.external.json"
    if external:
        try:
            source = Path(external).resolve(strict=True)
            if source.is_relative_to(root) or source.stat().st_size > 128:
                raise ValueError()
            key = base64.b64decode(source.read_bytes().strip(), altchars=b"-_", validate=True)
            if len(key) != 32 or (root / "vault.key").exists():
                raise ValueError()
            add("external_key", "pass", "Key file is readable and separate; existing vault decryption is checked at startup")
        except (OSError, ValueError):
            add("external_key", "fail", "Check the external key file and vault mode; no secret values were displayed")
    elif marker.exists():
        add("external_key", "fail", "This data directory requires TGWITNESS_VAULT_KEY_FILE")
    else:
        add("vault_mode", "warning", "Default local key mode; use encrypted storage for journal and attachments")
    if os.environ.get("TGWITNESS_TOKEN") and len(os.environ["TGWITNESS_TOKEN"]) < 24:
        add("panel_token", "fail", "TGWITNESS_TOKEN must contain at least 24 characters")
    from .anchor import find_openssl
    try:
        find_openssl()
        add("timestamp_verifier", "pass", "OpenSSL executable found; optional TSA interoperability is a separate check")
    except ValueError:
        add("timestamp_verifier", "warning", "OpenSSL not found; only external timestamp verification needs it")
    return {"ready": not any(c["status"] == "fail" for c in checks), "platform": platform.platform(),
            "interpreter": sys.executable, "data_directory": str(root), "checks": checks,
            "scope": "Local startup prerequisites only; no Telegram, proxy, coverage or forensic certification test"}


def print_report(report, as_json=False):
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print("TgWitness deployment check")
        print("Python:", report["interpreter"])
        print("Data:", report["data_directory"])
        for item in report["checks"]:
            print("[" + item["status"].upper() + "] " + item["name"] + ": " + item["detail"])
        print("Ready to attempt startup." if report["ready"] else "Resolve failed checks before starting.")
        print(report["scope"])
