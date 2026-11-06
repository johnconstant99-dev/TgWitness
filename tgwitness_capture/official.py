"""Owned official Web A browser. No Telegram protocol or client-internal calls.

The control API exposes named UI operations, never arbitrary input, JavaScript,
URLs, CDP or profiles. Host administrators remain outside this local trust boundary.
"""
import asyncio
import ipaddress
import os
import secrets
import time
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .adapters import BrowserCapture
from .format import canonical, digest, utcnow

URL = "https://web.telegram.org/a/"
ADAPTER = "telegram-web-a-dom-v1"
SOURCE_REVIEW = "6002824b6532f3d913997ce496d9ab5f9b86bc22"
CHAT_LIST = "#LeftColumn .chat-list .Chat"
MESSAGES = "#MiddleColumn .MessageList:visible"
TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
RENDERED_TEXT = (Path(__file__).with_name("static") / "official-rendered-text.js").read_text(encoding="utf-8")


class OfficialOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["passive", "paced"] = "passive"
    egress: Literal["http", "socks5", "cloudflare_warp", "direct"] = "http"
    proxy_server: str = Field(default="", max_length=2048)
    proxy_username_env: str = ""
    proxy_password_env: str = ""
    expected_ip: str = ""
    min_pause_seconds: float = Field(default=4.0, ge=2, le=120)
    max_pause_seconds: float = Field(default=10.0, ge=2, le=300)
    scroll_pixels: int = Field(default=320, ge=80, le=600)
    max_steps: int = Field(default=300, ge=1, le=5000)
    session_minutes: int = Field(default=30, ge=1, le=120)
    max_storage_mib: int = Field(default=3072, ge=128, le=6144)
    require_video: bool = True
    drand: bool = True

    @field_validator("proxy_server")
    @classmethod
    def proxy_url(cls, value):
        if not value:
            return value
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError:
            port = None
        if (parsed.scheme not in {"http", "socks5"} or not parsed.hostname or not port
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or any(c.isspace() or ord(c) < 32 or c == "\\" for c in value)):
            raise ValueError("Use an explicit HTTP or SOCKS5 proxy host and port, without credentials or a path")
        return value.rstrip("/")

    @field_validator("expected_ip")
    @classmethod
    def ip(cls, value):
        return str(ipaddress.ip_address(value)) if value else ""

    @field_validator("proxy_username_env", "proxy_password_env")
    @classmethod
    def env_name(cls, value):
        if value and (not value.isascii() or not value.replace("_", "").isalnum() or len(value) > 128):
            raise ValueError("Invalid secret environment variable name")
        return value

    @model_validator(mode="after")
    def consistent(self):
        if self.max_pause_seconds < self.min_pause_seconds:
            raise ValueError("Maximum pause must not be shorter than minimum pause")
        if self.egress == "direct":
            if self.proxy_server or self.proxy_username_env or self.proxy_password_env:
                raise ValueError("Direct mode cannot include proxy settings")
        elif not self.proxy_server:
            raise ValueError("A proxy endpoint is required unless direct mode is explicitly selected")
        if self.egress == "socks5" and not self.proxy_server.startswith("socks5://"):
            raise ValueError("SOCKS5 requires a SOCKS5 endpoint")
        if self.egress == "http" and not self.proxy_server.startswith("http://"):
            raise ValueError("HTTP requires an HTTP proxy endpoint")
        if self.proxy_server.startswith("socks5://") and (self.proxy_username_env or self.proxy_password_env):
            raise ValueError("Chromium does not support authenticated SOCKS5; use an isolated HTTP bridge")
        return self

    def receipt(self):
        return {**self.model_dump(exclude={"proxy_username_env", "proxy_password_env"}),
                "has_proxy_credentials": bool(self.proxy_username_env or self.proxy_password_env),
                "direct_fallback": False, "ip_check": "periodic; not proof of every connection",
                "cloudflare_binding_verified": False}


class GuardStopped(ValueError):
    pass


class PaceWait(ValueError):
    pass


def official_url(value):
    parsed = urlsplit(value)
    return (parsed.scheme == "https" and parsed.netloc == "web.telegram.org"
            and parsed.path in {"/a", "/a/"} and not parsed.query)


class OfficialBrowser(BrowserCapture):
    def __init__(self, options, journal, *, headless=False):
        super().__init__("", URL)
        self.options = options
        self.journal = journal
        self.headless = headless
        self.context = self.page = None
        self.phase = "created"
        self.reason = None
        self.selected_url = None
        self.selected_title = None
        self.handles = {}
        self.steps = 0
        self.next_step = 0
        self.started = 0
        self.checked_route = 0
        self.exit_ip = None
        self.password_attempts = 0
        self.stop_requested = False

    def status(self):
        return {"phase": self.phase, "reason": self.reason, "mode": self.options.mode,
                "adapter": ADAPTER, "selected_chat": self.selected_title,
                "source": self.selected_url, "source_locked": bool(self.started),
                "steps": self.steps, "exit_ip": self.exit_ip, "options": self.options.receipt(),
                "environment_attested": False, "logout_confirmed": getattr(self, "logout_confirmed", False),
                "limits": ["Official client may send read receipts and online status",
                           "No guarantee against Telegram restrictions",
                           "Rendered observations only; not complete account history",
                           "Local host administrator is trusted; no sealed attestation is asserted"]}

    async def connect(self):
        if self.page is None:
            raise ValueError("Open the official client first")

    async def open(self):
        if self.phase != "created":
            raise ValueError("This procedure has already opened a client; finish it before starting another")
        from playwright.async_api import async_playwright
        direct = self.options.egress == "direct"
        proxy = None if direct else {"server": self.options.proxy_server, "bypass": "<-loopback>"}
        for key in ("username", "password"):
            name = getattr(self.options, "proxy_" + key + "_env")
            if name:
                if not os.environ.get(name):
                    raise ValueError("Configured proxy secret is unavailable")
                proxy[key] = os.environ[name]
        self.runtime = await async_playwright().start()
        try:
            self.browser = await self.runtime.chromium.launch(
                headless=self.headless, chromium_sandbox=True, proxy=proxy,
                args=["--disable-quic", "--disable-dev-shm-usage", "--no-first-run",
                      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                      *(["--no-proxy-server"] if direct else [])])
            self.context = await self.browser.new_context(
                viewport={"width": 1280, "height": 720}, locale="en-US",
                accept_downloads=False, service_workers="block", permissions=[])
            self.context.set_default_timeout(5000)
            await self.context.add_init_script(path=Path(__file__).parent / "static" / "official-guard.js")
            await self.context.route("**/*", self._route)
            self.context.on("page", self._new_page)
            self.page = await self.context.new_page()
            self.target_id = "official-" + secrets.token_hex(16)
            await self.check_route()
            await self.page.goto(URL, wait_until="domcontentloaded", timeout=45000)
            self.phase = "login"
            self.journal.append("official.opened", {"adapter": ADAPTER, "source_review": SOURCE_REVIEW,
                                "url": URL, "browser_version": self.browser.version,
                                "settings": self.options.receipt(), "login_recorded": False,
                                "profile": "fresh non-persistent browser context", "environment_attested": False})
        except BaseException:
            await self.close()
            self.phase, self.reason = "stopped", "ClientOpenFailed"
            raise
        return self.status()

    async def _route(self, route):
        request = route.request
        if request.is_navigation_request() and not official_url(request.url):
            self.reason = "UnexpectedNavigation"
            self.stop_requested = True
            await route.abort("blockedbyclient")
        else:
            await route.continue_()

    def _new_page(self, page):
        if self.page is not None and page is not self.page:
            self.stop_requested = True
            self.reason = "UnexpectedWindow"
            asyncio.create_task(page.close())

    async def check_route(self):
        if self.context is None:
            raise GuardStopped("ClientUnavailable")
        response = await self.context.request.get(TRACE, timeout=10000, max_redirects=0)
        try:
            if response.status != 200 or response.url != TRACE:
                raise GuardStopped("EgressCheckUnavailable")
            body = await response.body()
            if len(body) > 8192:
                raise GuardStopped("EgressCheckInvalid")
            values = dict(line.split("=", 1) for line in body.decode("ascii").splitlines() if "=" in line)
            address = str(ipaddress.ip_address(values.get("ip", "")))
            if self.options.expected_ip and address != self.options.expected_ip:
                raise GuardStopped("UnexpectedEgressAddress")
            if self.exit_ip is not None and address != self.exit_ip:
                raise GuardStopped("EgressAddressChanged")
            self.exit_ip = address
            self.checked_route = time.monotonic()
            self.journal.append("official.egress_observed", {"ip": address, "observed_at": utcnow(),
                                "provider": self.options.egress, "endpoint": TRACE,
                                "scope": "browser-context route probe; does not prove every connection"})
        finally:
            await response.dispose()

    async def login_state(self):
        await self.connect()
        if not official_url(self.page.url):
            raise GuardStopped("UnexpectedOrigin")
        if await self.page.locator("#auth-password-form").is_visible():
            return "password"
        if await self.page.locator("#auth-qr-form").is_visible():
            return "qr"
        if await self.page.locator("#LeftColumn .chat-list").first.is_visible():
            return "ready"
        return "loading"

    async def screen(self):
        await self.connect()
        if not official_url(self.page.url):
            raise GuardStopped("UnexpectedOrigin")
        return await self.page.screenshot(type="jpeg", quality=65, full_page=False)

    async def password(self, value):
        if self.phase != "login" or await self.login_state() != "password":
            raise ValueError("Password input is only available on the official login form before recording")
        if self.password_attempts >= 3:
            raise ValueError("Login attempt limit reached; finish this procedure")
        self.password_attempts += 1
        field = self.page.locator("#auth-password-form #sign-in-password")
        await field.fill(value)
        await field.press("Enter")
        # Do not record the password, response, field value or a login screenshot.

    async def chats(self):
        if self.phase not in {"login", "ready", "paused"} or await self.login_state() != "ready":
            raise ValueError("Complete QR login before choosing a chat")
        self.phase = "paused" if self.selected_url else "ready"
        rows = self.page.locator(CHAT_LIST)
        self.handles = {}
        result = []
        for i in range(min(await rows.count(), 500)):
            row = rows.nth(i)
            if not await row.is_visible():
                continue
            link = row.locator("a[href^='#']").first
            if not await link.count():
                continue
            href = await link.get_attribute("href")
            if not href or len(href) > 200 or not href[1:].replace("-", "").isdigit():
                continue
            title = (await row.locator(".title").first.inner_text())[:300]
            handle = secrets.token_hex(16)
            self.handles[handle] = (href, title)
            result.append({"handle": handle, "title": title})
        return result

    async def select_chat(self, handle):
        if self.phase not in {"ready", "paused"} or handle not in self.handles:
            raise ValueError("Refresh the visible chat list and choose one chat while paused")
        href, title = self.handles[handle]
        if self.started and self.selected_url and urlsplit(self.selected_url).fragment != href[1:]:
            raise ValueError("The recorded source cannot change after observation starts")
        # href is accepted only from the rendered list and restricted to numeric chat routes.
        match = self.page.locator(CHAT_LIST + " a[href='" + href + "']")
        if await match.count() != 1:
            raise ValueError("Chat list changed; refresh it before choosing")
        await match.click()
        await self.page.locator(MESSAGES).wait_for(state="visible")
        if not official_url(self.page.url) or urlsplit(self.page.url).fragment != href[1:]:
            raise GuardStopped("UnexpectedChatRoute")
        self.selected_url, self.selected_title = self.page.url, title
        self.phase = "ready"
        self.last_state = None
        self.journal.append("official.chat_selected", {"title": title, "visible_route": href,
                            "scope": "one visible chat; route is a client-rendered identifier"})

    async def arm(self):
        if self.phase not in {"ready", "paused"} or not self.selected_url:
            raise ValueError("Select one visible chat before starting")
        if self.stop_requested:
            raise GuardStopped(self.reason or "GuardStopped")
        await self.check_route()
        await self.page.evaluate("window.__tgwitnessGuard.arm()")
        self.phase = "observing"
        await self.assert_safe()
        if not self.started:
            self.started = time.monotonic()
        self.next_step = time.monotonic() + self.options.min_pause_seconds
        self.journal.append("official.started", {"adapter": ADAPTER, "settings": self.options.receipt(),
                            "settings_sha256": digest(canonical(self.options.receipt())),
                            "source": self.selected_url, "recording_starts_after_login": True})
        if self.options.drand:
            await self.beacon()

    async def assert_safe(self):
        if self.stop_requested or self.page is None or self.page.is_closed():
            raise GuardStopped(self.reason or "ClientUnavailable")
        if not official_url(self.page.url) or (self.selected_url and self.page.url != self.selected_url):
            raise GuardStopped("SourceChanged")
        state = await self.page.evaluate("window.__tgwitnessGuard.inspect()")
        if state["reason"]:
            raise GuardStopped(state["reason"])
        if await self.page.locator(MESSAGES).count() != 1:
            raise GuardStopped("UnsupportedMessageLayout")
        if time.monotonic() - self.checked_route >= 30:
            await self.check_route()

    async def beacon(self):
        from .beacon import CHAIN, GENESIS, PERIOD, RELAY, round_time, validate
        response = await self.context.request.get(RELAY + "latest", timeout=10000, max_redirects=0)
        try:
            if response.status != 200 or len(await response.body()) > 4096:
                raise GuardStopped("BeaconUnavailable")
            value = validate(await response.json())
        finally:
            await response.dispose()
        if abs(GENESIS + (value["round"] - 1) * PERIOD - time.time()) > 60:
            raise GuardStopped("BeaconNotFresh")
        previous = getattr(self, "beacon_round", 0)
        if value["round"] < previous:
            raise GuardStopped("BeaconWentBackwards")
        if value["round"] > previous:
            self.journal.append("official.drand", {**value, "chain": CHAIN,
                                "round_time": round_time(value["round"]),
                                "meaning": "not-before bound after independent relay comparison; no upper time bound"})
            self.beacon_round = value["round"]
            await self.page.evaluate("""round => {
              let el=document.getElementById('tgwitness-beacon');
              if(!el){el=document.createElement('div');el.id='tgwitness-beacon';
                Object.assign(el.style,{position:'fixed',bottom:'4px',right:'4px',zIndex:'2147483646',
                  color:'#fff',background:'#101827',padding:'4px',font:'12px monospace',pointerEvents:'none'});
                document.body.append(el);}
              el.textContent='drand round '+round+' · not-before only';
            }""", value["round"])
        self.checked_beacon = time.monotonic()

    async def scroll(self, direction="older"):
        if self.phase != "observing" or self.stop_requested:
            raise ValueError("Start recording before scrolling")
        await self.assert_safe()
        if time.monotonic() < self.next_step:
            raise PaceWait("Wait for the configured pause before scrolling again")
        if self.steps >= self.options.max_steps:
            raise GuardStopped("StepLimitReached")
        delta = self.options.scroll_pixels * (-1 if direction == "older" else 1)
        # Scroll only the rendered list, never its internal state or Telegram transport.
        await self.page.locator(MESSAGES).evaluate("(element, delta) => element.scrollBy({top: delta, behavior: 'smooth'})", delta)
        self.steps += 1
        self.journal.append("official.action", {"action": "scroll", "direction": direction,
                            "pixels": abs(delta), "step": self.steps})
        self.next_step = time.monotonic() + secrets.SystemRandom().uniform(
            self.options.min_pause_seconds, self.options.max_pause_seconds)

    async def tick(self):
        if self.phase != "observing":
            return
        await self.assert_safe()
        if self.options.drand and time.monotonic() - getattr(self, "checked_beacon", 0) >= 30:
            await self.beacon()
        if time.monotonic() - self.started >= self.options.session_minutes * 60:
            raise GuardStopped("SessionLimitReached")
        used = sum(p.stat().st_size for p in self.journal.objects.iterdir() if p.is_file())
        used += sum(p.stat().st_size for p in self.journal.pending.rglob("*") if p.is_file())
        if used >= self.options.max_storage_mib * 1024 * 1024:
            raise GuardStopped("StorageLimitReached")
        if self.options.mode == "paced" and time.monotonic() >= self.next_step:
            await self.scroll()

    async def pause(self, reason=None):
        if self.phase == "observing":
            self.phase = "stopped" if reason else "paused"
            self.reason = reason
            self.stop_requested = bool(reason)
            self.journal.append("official.stopped" if reason else "official.paused", {"reason": reason, "steps": self.steps})
        # Keep the input guard armed while paused. Pausing never grants general control.

    async def targets(self):
        return [(self.page, self.target_id, self.page.url)] if self.page is not None else []

    async def rendered_text(self, page):
        return await page.locator("body").evaluate(RENDERED_TEXT, timeout=10000)

    async def capture(self, journal, settings, max_interval, force=False):
        await self.assert_safe()
        result = await super().capture(journal, settings, max_interval, force)
        await self.assert_safe()
        if result:
            metadata, artifacts, observed = result
            messages = await self.page.locator(MESSAGES + " .Message[data-message-id]").evaluate_all("""elements => {
              const text = """ + RENDERED_TEXT + """;
              return elements.slice(0,500).map(el => ({
                rendered_id: el.getAttribute('data-message-id'), rendered_text: text(el).slice(0,100000),
                author: text(el.querySelector('.sender-name')) || null,
                displayed_time: el.querySelector('.time')?.getAttribute('title') || el.querySelector('.time')?.innerText || null,
                reply: text(el.querySelector('.embedded-message')) || null,
                reactions: text(el.querySelector('.Reactions')) || null,
                deletion_observed: false, telegram_origin_independently_proven: false
            })); }""")
            artifacts.append(journal.artifact(canonical(messages), "rendered_messages", "application/json"))
            metadata.update({"adapter": ADAPTER, "source": "official-telegram-web-a",
                             "environment_attested": False, "all_messages_observed": False})
            return metadata, artifacts, observed
        return None

    async def finish(self):
        if self.phase == "finished":
            return self.status()
        self.phase = "finishing"
        self.logout_confirmed = False
        try:
            if self.page and not self.page.is_closed() and official_url(self.page.url):
                await self.page.evaluate("window.__tgwitnessGuard.disarmForLogout()")
                # Narrow English UI path. Unknown layouts fail closed; no internal logout RPC.
                self.page.set_default_timeout(3000)
                menu = self.page.locator("#LeftColumn .DropdownMenu .Button").first
                await menu.click()
                await self.page.get_by_role("menuitem", name="Settings", exact=True).click()
                await self.page.locator(".settings-main-header .settings-more-menu .Button").click()
                await self.page.get_by_role("menuitem", name="Log Out", exact=True).click()
                await self.page.locator(".Modal.open").get_by_role("button", name="Log Out", exact=True).click()
                await self.page.locator("#auth-qr-form, #auth-phone-number-form").first.wait_for(state="visible", timeout=10000)
                self.logout_confirmed = True
        except Exception:
            pass
        finally:
            await self.close()
            self.phase = "finished"
            self.journal.append("official.finished", {"logout_confirmed": self.logout_confirmed,
                                "profile_context_closed": True,
                                "required_action": None if self.logout_confirmed else "Revoke this session from a trusted Telegram device"})
        return self.status()

    async def close(self):
        try:
            if self.context is not None:
                await self.context.close()
            if self.browser is not None:
                await self.browser.close()
        finally:
            if self.runtime is not None:
                await self.runtime.stop()
            self.context = self.page = self.browser = self.runtime = None
