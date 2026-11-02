"""Offline report layouts. Presentation never changes the selected records."""
from pathlib import Path
from typing import Literal

Design = Literal["classic", "quire", "meridian", "atlas", "ledger", "horizon", "reading_series", "ledger_margin"]
DESIGNS = ("classic", "quire", "meridian", "atlas", "ledger", "horizon", "reading_series", "ledger_margin")
LEGACY = {"dossier": "classic", "analytical": "atlas", "editorial": "quire"}


def canonical(value):
    """Migrate the three early Report Studio labels without accepting unknown styles."""
    return LEGACY.get(value, value) if isinstance(value, str) else value


def normalized(value):
    """Internal render calls also accept older options, which predate the style picker."""
    value = canonical(value)
    return value if isinstance(value, str) and value in DESIGNS else "classic"


CSS = Path(__file__).with_name("report_styles.css").read_text(encoding="utf-8")
