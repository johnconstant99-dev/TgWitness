"""Explicitly configured, bounded AI requests through the workspace network route."""
import asyncio
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from . import netclient


def endpoint(value):
    value = value.strip().rstrip("/")
    parsed = urlsplit(value)
    if (parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise ValueError("Enter an HTTP endpoint without credentials, query or fragment.")
    if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Use HTTPS for an external AI endpoint.")
    return value


def local_endpoint():
    return endpoint(os.environ.get("TGWITNESS_AI_LOCAL_ENDPOINT", "http://127.0.0.1:11434"))


class ProviderSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    provider: Literal["ollama", "compatible"] = "ollama"
    endpoint: str = Field(default="http://127.0.0.1:11434", max_length=2048)
    model: str = Field(default="", max_length=160)
    api_key: SecretStr | None = None
    clear_key: bool = False
    context_chars: int = Field(default=12000, ge=2000, le=64000)
    output_tokens: int = Field(default=1500, ge=128, le=4096)
    timeout_seconds: int = Field(default=60, ge=5, le=180)
    daily_requests: int = Field(default=30, ge=1, le=1000)
    input_per_million: float | None = Field(default=None, ge=0, le=10000)
    output_per_million: float | None = Field(default=None, ge=0, le=10000)
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")

    @model_validator(mode="after")
    def valid(self):
        self.endpoint = endpoint(self.endpoint)
        if self.provider == "ollama" and self.endpoint != local_endpoint():
            raise ValueError("Set the local Ollama endpoint with TGWITNESS_AI_LOCAL_ENDPOINT on the server.")
        if self.enabled and not self.model.strip():
            raise ValueError("Choose a model before enabling AI.")
        if self.api_key and not re.fullmatch(r"[!-~]{1,4096}", self.api_key.get_secret_value()):
            raise ValueError("The API key must contain only printable ASCII characters.")
        return self


def settings(state):
    defaults = ProviderSettings(endpoint=local_endpoint()).model_dump(exclude={"api_key", "clear_key"})
    return defaults | state.store.get_setting("ai", {})


def enabled(state, config=None):
    """Panel capability only: no provider probe and no secret access."""
    config = settings(state) if config is None else config
    return bool(config.get("enabled") and str(config.get("model") or "").strip()
                and not state.store.get_setting("demo", False))


def fingerprint(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def public(state):
    config = settings(state)
    return {**config, "has_key": bool(state.vault.read("ai").get("api_key")),
            "local_endpoint": local_endpoint(), "usage": state.store.get_setting("ai_usage", {}),
            "processing": "server-local" if urlsplit(config["endpoint"]).hostname in
            ("127.0.0.1", "localhost", "::1") else "configured-endpoint",
            "route": state.collector.outside_route().kind}


def configure(state, body):
    secret = state.vault.read("ai")
    if body.clear_key:
        secret.pop("api_key", None)
    if body.api_key:
        secret["api_key"] = body.api_key.get_secret_value()
    state.vault.save("ai", secret)
    state.store.set_setting("ai", body.model_dump(exclude={"api_key", "clear_key"}))
    return public(state)


class Provider:
    def __init__(self):
        self.slots = asyncio.Semaphore(2)
        self.busy = set()

    async def complete(self, state, messages, expected=None):
        config = settings(state)
        if not config["enabled"]:
            raise ValueError("AI is disabled for this workspace.")
        if expected and expected != fingerprint(config):
            raise ValueError("AI settings changed. Review the data preview again.")
        if state.store.get_setting("demo", False):
            raise ValueError("Configure AI in your own installation.")
        if len(json.dumps(messages, ensure_ascii=False)) > config["context_chars"] + 6000:
            raise ValueError("The selected context exceeds the configured limit.")
        key = str(state.store.root)
        if key in self.busy:
            raise ValueError("An AI request is already running for this workspace.")
        self.busy.add(key)
        try:
            async with asyncio.timeout(config["timeout_seconds"]):
                async with self.slots:
                    current = settings(state)
                    if not enabled(state, current):
                        raise ValueError("AI is disabled for this workspace.")
                    if fingerprint(current) != fingerprint(config):
                        raise ValueError("AI settings changed. Review the data preview again.")
                    day = datetime.now(timezone.utc).date().isoformat()
                    usage = state.store.get_setting("ai_usage", {})
                    if usage.get("day") != day:
                        usage = {"day": day, "requests": 0, "input_tokens": 0, "output_tokens": 0}
                    if usage["requests"] >= config["daily_requests"]:
                        raise ValueError("The daily AI request budget has been reached.")
                    usage["requests"] += 1
                    state.store.set_setting("ai_usage", usage)
                    headers = {"Content-Type": "application/json"}
                    secret = state.vault.read("ai").get("api_key")
                    if secret:
                        headers["Authorization"] = "Bearer " + secret
                    request = {"model": config["model"], "messages": messages, "stream": False}
                    if config["provider"] == "ollama":
                        request.update(format="json", options={"num_predict": config["output_tokens"]})
                        path = "/api/chat"
                    else:
                        request.update(response_format={"type": "json_object"}, max_completion_tokens=config["output_tokens"])
                        path = "/chat/completions"
                    local = config["provider"] == "ollama" and config["endpoint"] == local_endpoint()
                    _, _, raw = await netclient.request("POST", config["endpoint"] + path,
                        state.collector.outside_route(), headers=headers, body=json.dumps(request).encode(),
                        timeout=config["timeout_seconds"], limit=128 * 1024, private=local)
                    result = json.loads(raw)
                    if config["provider"] == "ollama":
                        text = result["message"]["content"]
                        counts = {"input_tokens": result.get("prompt_eval_count"), "output_tokens": result.get("eval_count")}
                        if not result.get("done") or result.get("done_reason") == "length":
                            raise ValueError("The model response was incomplete. Reduce the selected context.")
                    else:
                        choice = result["choices"][0]
                        if choice.get("finish_reason") != "stop":
                            raise ValueError("The model response was incomplete. Reduce the selected context.")
                        text = choice["message"]["content"]
                        reported = result.get("usage") or {}
                        counts = {"input_tokens": reported.get("prompt_tokens"), "output_tokens": reported.get("completion_tokens")}
                    counts = {k: v for k, v in counts.items() if type(v) is int and 0 <= v <= 10000000}
                    for k, value in counts.items():
                        usage[k] += value
                    state.store.set_setting("ai_usage", usage)
                    cost = None
                    if len(counts) == 2 and all(config[k] is not None for k in ("input_per_million", "output_per_million")):
                        cost = {"amount": (counts["input_tokens"] * config["input_per_million"] +
                                          counts["output_tokens"] * config["output_per_million"]) / 1000000,
                                "currency": config["currency"], "basis": "configured tariffs"}
                    return json.loads(text), {"provider": config["provider"], "model": config["model"],
                                             "endpoint": config["endpoint"], "tokens": counts, "cost": cost}
        except (KeyError, TypeError, IndexError, json.JSONDecodeError):
            raise ValueError("The provider returned an unsupported response.") from None
        except netclient.HTTPError as exc:
            raise ValueError("AI endpoint returned HTTP " + str(exc.status) + ".") from None
        finally:
            self.busy.discard(key)
