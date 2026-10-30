"""Uvicorn diagnostics for console and windowless launches."""
import copy
import os
import sys

from uvicorn.config import LOGGING_CONFIG


def server_logging(root):
    config = copy.deepcopy(LOGGING_CONFIG)
    if sys.stdout is not None and sys.stderr is not None:
        return config
    # pythonw has no console streams. Keep startup failures visible without
    # enabling HTTP access logs or logging request bodies/authorization headers.
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = root / "logs"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "server.log"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(descriptor)
    config["formatters"] = {"default": {
        "format": "%(asctime)s %(levelname)s %(message)s",
    }}
    config["handlers"] = {"default": {
        "class": "logging.handlers.RotatingFileHandler", "formatter": "default",
        "filename": str(path), "encoding": "utf-8", "maxBytes": 5 * 1024**2, "backupCount": 2,
    }}
    config["loggers"]["uvicorn.access"]["handlers"] = ["default"]
    return config
