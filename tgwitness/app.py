import ipaddress
import re
import time as time
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    model_validator,
)

from . import __version__
from . import dossier as dossier
from . import i18n
from .message_selection import Selection
from .account_import import IMPORT_REQUEST_LIMIT
from .anchoring import gateway_rows as gateway_rows
from .downloads import RetainedDownload as RetainedDownload
from .evidence import export_file as export_file
from . import replica
from . import alerts
from .network import NetworkConfig, RoutePolicy
from . import report
from . import handover
from . import modes


class Credentials(BaseModel):
    api_id: int | None = Field(default=None, gt=0, le=2147483647)
    api_hash: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{32}$")
    session: str = Field(default="", max_length=4096)
    expected_user_id: int | None = Field(default=None, gt=0)
    client_profile: dict[str, object] | None = None

    @model_validator(mode="after")
    def complete_api_pair(self):
        from .client_identity import validate

        if self.client_profile is not None:
            self.client_profile = validate(self.client_profile)
        if (self.api_id is None) != (self.api_hash is None):
            raise ValueError(
                "Provide both API ID and API hash, or use this workspace's saved credentials."
            )
        return self


class PhoneLogin(Credentials):
    phone: str = Field(pattern=r"^\+[0-9]{7,16}$")


class AccountFile(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=IMPORT_REQUEST_LIMIT)


class AccountImport(BaseModel):
    files: list[AccountFile] = Field(min_length=1, max_length=4)
    passcode: str = Field(default="", max_length=512)
    new_session: bool = False


class IndependentSession(Credentials):
    formats: list[
        Literal[
            "Account JSON",
            "Telethon SQLite",
            "Pyrogram SQLite",
            "TData ZIP",
            "Telethon StringSession",
        ]
    ] = Field(default_factory=list, max_length=4)
    two_factor_password: str = Field(default="", max_length=512)


class Phone(BaseModel):
    phone: str = Field(pattern=r"^\+[0-9]{7,16}$")


class Code(BaseModel):
    code: str = Field(min_length=3, max_length=12, pattern=r"^[0-9 -]+$")


class Password(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class GatewayLog(BaseModel):
    account: str = Field(pattern=r"^[0-9a-f]{32}$")
    location_id: str
    address: str = ""
    token: str = Field(default="", max_length=400)

    @model_validator(mode="after")
    def plain(self):
        self.location_id = self.location_id.strip().lower().replace("-", "")
        if not re.fullmatch(r"[0-9a-f]{32}", self.location_id):
            raise ValueError(
                "Enter the Gateway DNS location ID from Cloudflare Zero Trust."
            )
        self.address = self.address.strip()
        if self.address:
            try:
                ipaddress.ip_address(self.address)
            except ValueError:
                raise ValueError(
                    "Enter this server's public IP address, or leave the field empty."
                ) from None
        self.token = self.token.strip()
        if self.token.startswith("cfk_") or (
            self.token and not re.fullmatch(r"[A-Za-z0-9_-]{20,400}", self.token)
        ):
            raise ValueError(
                "Paste a Cloudflare API token with read access, not the Global API Key."
            )
        return self


class SourceCheck(BaseModel):
    repository: str = Field(min_length=3, max_length=200)
    ref: str = Field(min_length=1, max_length=200)


class AlertUpdate(alerts.AlertSettings):
    urls: list[str] | None = Field(default=None, max_length=20)
    add_urls: list[str] = Field(default=[], max_length=20)


class ExportPassword(BaseModel):
    password: str = Field(min_length=12, max_length=256)
    encryption: Literal["zip", "tgwpw"] = "zip"


class HandoverRequest(handover.Options):
    password: str | None = Field(default=None, min_length=12, max_length=256)
    encryption: Literal["zip", "tgwpw"] = "zip"
    language: str | None = Field(default=None, max_length=16)


class ModeChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: modes.Mode
    confirm_downgrade: StrictBool = False
    reason: Literal["chosen", "later"] = "chosen"


class Target(BaseModel):
    chat_id: int
    enabled: bool
    priority: bool | None = None


class TargetPriority(BaseModel):
    chat_id: int
    priority: bool


class TargetBatch(BaseModel):
    chat_ids: list[int] = Field(min_length=1, max_length=500)
    enabled: bool | None = None
    priority: bool | None = None
    remove: StrictBool = False

    @model_validator(mode="after")
    def action_required(self):
        if self.remove:
            if self.enabled is not None or self.priority is not None:
                raise ValueError("Remove cannot be combined with enabled or priority.")
            return self
        if self.enabled is None and self.priority is None:
            raise ValueError("Choose enabled, priority, or remove.")
        return self


class IgnoreSources(BaseModel):
    chat_ids: list[StrictInt] = Field(min_length=1, max_length=500)
    ignored: StrictBool

    @model_validator(mode="after")
    def valid_chat_ids(self):
        if any(
            chat_id == 0 or not -(2**53) < chat_id < 2**53 for chat_id in self.chat_ids
        ):
            raise ValueError("Invalid chat ID.")
        return self


class ClearMediaQueue(BaseModel):
    through_seq: StrictInt = Field(ge=0, lt=2**53)


class DossierSwitch(BaseModel):
    enabled: bool


class WitnessTokenCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class ProxyLink(BaseModel):
    link: str = Field(min_length=1, max_length=2048)


class ProxyListUpload(BaseModel):
    label: str = Field(default="", max_length=120)
    text: str = Field(min_length=1, max_length=1024 * 1024)


class GitHubToken(BaseModel):
    token: str = Field(default="", max_length=300)


class ReplicaUpdate(replica.ReplicaSettings):
    access_key: str = Field(default="", max_length=256, pattern=r"^\S*$")
    secret_key: str = Field(default="", max_length=256, pattern=r"^\S*$")


class Snapshot(BaseModel):
    chat_id: int
    limit: int = Field(default=100, ge=1, le=10000)


class ParametersUpdate(BaseModel):
    values: dict[str, bool | int | float | list[str] | None] = Field(max_length=200)


class EndSession(BaseModel):
    hash: str = Field(pattern=r"^-?[0-9]{1,20}$")


class WitnessProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool = False
    chat_id: StrictInt | None = None
    witness: str | None = Field(default=None, pattern=r"^(default|[a-f0-9]{32})$")


class AccountPassword(BaseModel):
    current_password: str | None = Field(default=None, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)
    hint: str = Field(default="", max_length=128)


class ChatExport(BaseModel):
    chat_id: int
    language: str | None = Field(default=None, max_length=16)
    files: Literal["download", "hashes", "skip"] | None = None


class MultiExportStart(BaseModel):
    chat_id: int
    lead: str = Field(default="default", max_length=64)
    profiles: list[str] = Field(default_factory=list, max_length=256)
    selection: Selection = Field(default_factory=Selection)
    transport: Literal["regular", "takeout"] = "regular"
    username: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{3,31}$")


class ExportPlan(BaseModel):
    link: str = Field(min_length=2, max_length=300)


class ProfileCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    group: str | None = Field(default=None, max_length=40)


class ProfileGroup(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    template: str | None = Field(default=None, max_length=40)
    sections: list[str] | None = Field(default=None, max_length=10)


class ProfileGroupAssign(BaseModel):
    group: str | None = Field(default=None, max_length=40)


class ProfileImport(AccountImport):
    label: str = Field(default="", max_length=80)
    group: str | None = Field(default=None, max_length=40)
    api_id: int | None = Field(default=None, gt=0)
    api_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    route: Literal["warp", "mtproxy", "direct"] | None = None
    route_consent: bool = False


class RoutePolicyUpdate(RoutePolicy):
    outside_proxy: NetworkConfig | None = None
    remove_outside_proxy: bool = False


class AccessLogin(BaseModel):
    token: str = Field(min_length=1, max_length=512)


def panel_language(request):
    return i18n.pick(
        request.cookies.get(i18n.COOKIE), request.headers.get("accept-language")
    )


def client_languages(request):
    from .client_identity import language_defaults

    return language_defaults(
        panel_language(request),
        request.headers.get("x-tgwitness-system-language")
        or request.headers.get("accept-language"),
    )


def report_options(store, request, language=None):
    options = report.resolved(store, panel_language(request))
    if language:
        if language not in i18n.LANGUAGES:
            raise HTTPException(422, "Unsupported report language")
        options["language"] = language
    return options


def create_app(
    data_dir=None,
    demo=False,
    client_factory=None,
    token_override=None,
    allow_profiles=True,
    account_guard=None,
    proxy_pool=None,
    access=None,
    profile_id="default",
):
    from .api.context import ApplicationContext
    from .api.registration import register

    context = ApplicationContext(
        data_dir,
        demo,
        client_factory,
        token_override,
        allow_profiles,
        account_guard,
        proxy_pool,
        access,
        profile_id,
    )
    app = FastAPI(
        title="TgWitness",
        version=__version__,
        lifespan=context.lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    context.app = app
    app.state.api_context = context
    register(app, context)
    return app
