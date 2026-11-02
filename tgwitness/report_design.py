from pathlib import Path
from typing import Literal

Design = Literal["classic", "quire", "meridian", "atlas", "ledger", "horizon", "reading_series", "ledger_margin"]
DESIGNS = ("classic", "quire", "meridian", "atlas", "ledger", "horizon", "reading_series", "ledger_margin")
LEGACY = {"dossier": "classic", "analytical": "atlas", "editorial": "quire"}


def canonical(value):
    return LEGACY.get(value, value) if isinstance(value, str) else value


def normalized(value):
    value = canonical(value)
    return value if isinstance(value, str) and value in DESIGNS else "classic"


CSS = Path(__file__).with_name("report_styles.css").read_text(encoding="utf-8")
