import hashlib
import importlib.metadata
import platform
import time
import uuid
from pathlib import Path

from . import __version__
from .store import canonical, utcnow
from .network import NetworkConfig
from .monitoring import capture_settings, monitoring_settings


LEGACY_SOURCE_POLICY = "tgwitness-source-v1"
SOURCE_POLICY = "tgwitness-package-v2"


def measured_path(path, policy=SOURCE_POLICY):
    path = Path(path)
    if policy == LEGACY_SOURCE_POLICY:
        return path.suffix in (".py", ".js", ".css", ".html", ".svg") and "__pycache__" not in path.parts
    if policy != SOURCE_POLICY:
        raise ValueError("Unknown source measurement policy: " + str(policy))
    return not (set(path.parts) & {"__pycache__", ".git", ".pytest_cache", ".ruff_cache", ".mypy_cache"}) \
        and path.suffix not in (".pyc", ".pyo") and path.name not in (".DS_Store", "README.md")


def source_files(root=Path(__file__).parent, policy=SOURCE_POLICY):
    measured_path("", policy)
    files = {}
    for source in sorted(Path(root).rglob("*")):
        if source.is_file() and measured_path(source.relative_to(root), policy):
            files[source.relative_to(root).as_posix()] = hashlib.sha256(source.read_bytes()).hexdigest()
    return files


def source_tree_sha256(files):
    return hashlib.sha256(canonical(files)).hexdigest()


def run_receipt(store, vault):
    files = source_files()
    dependencies = {}
    for name in ("telethon", "cryptography", "fastapi", "uvicorn", "qrcode"):
        try:
            dependencies[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            dependencies[name] = "unknown"
    return {
        "run_id": uuid.uuid4().hex, "software": "TgWitness", "version": __version__,
        "started_at": utcnow(), "monotonic_ns": time.monotonic_ns(),
        "python": platform.python_version(), "os": platform.system(),
        "dependencies": dependencies, "source_tree_sha256": source_tree_sha256(files),
        "source_policy": SOURCE_POLICY, "source_files": files, "public_key": vault.public_key,
        "account": store.get_setting("account", None), "targets": store.targets(),
        "network": NetworkConfig.model_validate(vault.read("network")).receipt(),
        "vault_key_mode": vault.key_mode,
        "capture": capture_settings(store),
        "monitoring": monitoring_settings(store),
        "attestation": "self-reported collector measurement; not an independent attestation or trusted timestamp",
    }
