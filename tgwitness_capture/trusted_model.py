from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Choice(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    case: str = Field(min_length=1, max_length=120)
    client: Literal["desktop", "web"] = "desktop"
    method: Literal["export", "visual", "hybrid"] = "hybrid"
    connector: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    pause_min: float = Field(default=2.0, ge=1, le=60)
    pause_max: float = Field(default=5.0, ge=1, le=120)

    @model_validator(mode="after")
    def compatible(self):
        if self.client == "web" and self.method != "visual":
            raise ValueError("Telegram Web supports visual collection only")
        if self.pause_min > self.pause_max:
            raise ValueError("Minimum pause must not exceed maximum pause")
        return self


class VisualNote(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    chat_id: int = Field(gt=0, lt=2**63)
    message_id: int = Field(gt=0, lt=2**63)
    text: str = Field(max_length=32768)
    frame_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class Scroll(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    direction: Literal["up", "down"]


class SetupInput(BaseModel):
    """Manual setup only; never available during capture. Contents are not journalled."""
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["click", "key", "text"]
    x: int = Field(default=0, ge=0, lt=1280)
    y: int = Field(default=0, ge=0, lt=720)
    key: Literal["Return", "Tab", "Escape", "BackSpace", "Up", "Down", "Left", "Right"] = "Tab"
    text: str = Field(default="", max_length=4096)


class ExportChoice(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=240)
