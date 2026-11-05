import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAMES = {
    "annotated-doc", "annotated-types", "anyio", "cffi", "click", "colorama", "cryptography",
    "fastapi", "greenlet", "h11", "idna", "importlib-metadata", "opentelemetry-api", "playwright",
    "pycparser", "pydantic", "pydantic-core", "pyee", "starlette", "typing-extensions", "typing-inspection",
    "uvicorn", "zipp", "exceptiongroup", "python-socks",
}


def selected_blocks():
    text = (ROOT / "deploy" / "browser.lock").read_text(encoding="utf-8")
    blocks = re.split(r"(?m)(?=^[a-zA-Z0-9][a-zA-Z0-9_.-]*==)", text)[1:]
    return [block.rstrip() for block in blocks if block.split("==", 1)[0].lower().replace("_", "-") in NAMES]


if __name__ == "__main__":
    contents = "# Copied from the project's reviewed deploy/browser.lock by lock_from_project.py.\n"
    contents += "# Runtime and optional CDP adapter only; install with --require-hashes.\n"
    contents += "\n".join(selected_blocks()) + "\n"
    (Path(__file__).parent / "requirements.lock").write_text(contents, encoding="utf-8", newline="\n")
