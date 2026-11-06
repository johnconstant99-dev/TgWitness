"""Create an independent authorization using a briefly connected imported donor."""
import asyncio
import hashlib
import secrets

from telethon.errors import PasswordHashInvalidError, SessionPasswordNeededError
from telethon.tl import functions

from . import api_pool, client_identity
from .account_import import session_key, validate_string
from .store import utcnow


async def create_session(collector, api_id, api_hash, session, expected_user_id=None,
                         client_profile=None, languages=None, formats=(), password=""):
    c = collector
    await c.wait_authorization_cleanup()
    if c.running:
        raise ValueError("Pause observation before creating an independent authorization.")
    session = validate_string(session)
    supplied = client_identity.validate(client_profile)
    key = session_key(session)
    donor_id = hashlib.sha256(key).hexdigest()
    pending = c.vault.read("independent_login")
    if pending and pending.get("donor") != donor_id:
        raise ValueError("Another independent login is pending. Import its original donor again to finish it.")
    release = c.account_guard(None, c, key=key) if c.account_guard else None
    release_account = donor = candidate = waiter = None

    def retain(saved=None):
        if candidate is not None and not (c.client is candidate and c.login_client is None):
            if saved is None:
                candidate.session.save()
                return
            if session_key(saved):
                if session_key(saved) == key:
                    raise ValueError("Independent login unexpectedly reused the donor authorization key.")
                c.lock_key(candidate)
                pending["session"] = saved
                c.vault.save("independent_login", pending)

    try:
        await c.cancel_login()
        await c.avatar_history.close()
        if c.client:
            await c.client.disconnect()
            c.client = None
        await c.ensure_route()

        def check_account(me):
            if me is None or getattr(me, "deleted", False):
                raise ValueError("The imported session is no longer authorized.")
            if getattr(me, "bot", False):
                raise ValueError("A user account is required; bot sessions are not supported.")
            if getattr(me, "restricted", False):
                raise ValueError("Telegram reports this account as restricted. Independent login stopped.")
            if expected_user_id is not None and me.id != expected_user_id:
                raise ValueError("The authorized Telegram account does not match the imported account ID.")
            existing = c.store.get_setting("account", {}) or {}
            if existing.get("id") is not None and existing["id"] != me.id:
                raise ValueError("This journal belongs to a different Telegram account. Create another account workspace.")

        async def healthy_account(client):
            me = await client.get_me()
            check_account(me)
            full = await client(functions.users.GetFullUserRequest("me"))
            if any(getattr(full.full_user, field, None) for field in (
                    "frozen_since_date", "frozen_until_date", "frozen_appeal_url")):
                raise ValueError("Telegram reports this account as frozen. Independent login stopped.")
            return me

        async def prepare_candidate():
            nonlocal candidate
            credentials = pending["credentials"]
            candidate = c.make_client(credentials["api_id"], credentials["api_hash"],
                                      pending.get("session", ""), credentials["client_profile"])
            save = candidate.session.save

            def save_pending():
                saved = save()
                retain(saved)
                return saved

            # Telethon saves negotiated keys before using them, including during
            # QR data-centre migration. Retain that key before token acceptance.
            candidate.session.save = save_pending
            c.login_client = candidate
            c.pending_credentials = dict(credentials)
            c.pending_account_id = pending["account_id"]
            c.pending_key_origin = "created"
            await c.connect_client(candidate)
            retain()

        if pending:
            if expected_user_id is not None and pending["account_id"] != expected_user_id:
                raise ValueError("The pending independent login belongs to a different Telegram account.")
            if c.account_guard:
                release_account = c.account_guard(pending["account_id"], c)
            await prepare_candidate()
            if await candidate.is_user_authorized():
                await healthy_account(candidate)
                await c.authorized()
                return {"step": "authorized"}
            if pending.get("password_required"):
                c.phase = "password_required"
                return await c.confirm_password(password) if password else {"step": "password"}

        if (api_id is None) != (api_hash is None):
            raise ValueError("Provide both donor API credentials or leave both empty.")
        if api_id is None:
            saved = c.vault.read("credentials")
            if session_key(saved.get("session")) == key:
                api_id, api_hash = saved["api_id"], saved["api_hash"]
            else:
                api_id, api_hash = next(pair for pair in api_pool.POOL if pair[0] == api_pool.DESKTOP_ID)
        donor = c.make_client(api_id, api_hash, session, supplied or None, languages)
        await c.connect_client(donor)
        if not await donor.is_user_authorized():
            raise ValueError("The imported session is no longer authorized.")
        me = await healthy_account(donor)
        if pending and me.id != pending["account_id"]:
            raise ValueError("The donor does not match the pending independent login.")
        if c.account_guard and release_account is None:
            release_account = c.account_guard(me.id, c)
        if candidate is None:
            new_id, new_hash = next(pair for pair in api_pool.POOL if pair[0] == api_pool.DESKTOP_ID)
            pending = {"donor": donor_id, "account_id": me.id, "credentials": {
                "api_id": new_id, "api_hash": new_hash,
                "client_profile": client_identity.resolve(new_id, languages, secrets.token_hex(32)),
                "session_origin": {"method": "qr_from_import", "formats": list(formats),
                                   "donor_api_id": api_id, "created_at": utcnow()}}}
            await prepare_candidate()
        qr = await candidate.qr_login()
        # Telethon must install its UpdateLoginToken listener before acceptance.
        waiter = asyncio.create_task(qr.wait(timeout=60))
        await asyncio.sleep(0)
        try:
            await asyncio.wait_for(donor(functions.auth.AcceptLoginTokenRequest(qr.token)), 30)
        finally:
            await donor.disconnect()
            donor = None
        try:
            await waiter
        except SessionPasswordNeededError:
            pending["password_required"] = True
            retain()
            c.phase = "password_required"
            return await c.confirm_password(password) if password else {"step": "password"}
        retain()
        await c.authorized()
        return {"step": "authorized"}
    except PasswordHashInvalidError:
        retain()
        return {"step": "password", "error": "The imported two-step verification password was rejected. Enter it again."}
    except BaseException:
        try:
            retain()
        finally:
            await c.cancel_login()
            c.phase = c.resting_phase()
        raise
    finally:
        if waiter is not None and not waiter.done():
            waiter.cancel()
        if waiter is not None:
            await asyncio.gather(waiter, return_exceptions=True)
        try:
            if donor is not None:
                await donor.disconnect()
        finally:
            if release_account:
                release_account()
            if release:
                release()
