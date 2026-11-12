from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HistoryOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    transport: Literal["standard", "takeout"] = "standard"
    media_workers: int = Field(default=2, ge=1, le=5)
    admin_log: bool = True
    compare_saved: bool = True
    observe_after: bool = False


def options_of(run):
    import json
    raw = json.loads(run["options"])
    return HistoryOptions(**raw) if raw else HistoryOptions(media_workers=1, admin_log=False)
