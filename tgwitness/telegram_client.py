import asyncio
import time
from contextvars import ContextVar

from telethon import TelegramClient, utils
from telethon.errors import FloodWaitError
from telethon.network.connection import ConnectionTcpFull
from telethon.network.connection.tcpmtproxy import TcpMTProxy
from telethon.tl import functions, types

from .rpc_pacing import bulk_request

_single_attempt = ContextVar("telegram_single_attempt", default=False)
_ACTIONS = (functions.messages.GetBotCallbackAnswerRequest,
            functions.messages.ImportChatInviteRequest, functions.channels.JoinChannelRequest)


class WitnessClient(TelegramClient):

    async def history_page(self, entity, *, limit, offset_id):
        """One raw page, retaining MessageEmpty instead of SDK iterator filtering."""
        peer = await self.get_input_entity(entity)
        result = await self(functions.messages.GetHistoryRequest(peer, offset_id, None, 0, limit, 0, 0, 0))
        entities = {utils.get_peer_id(item): item for item in [*result.users, *result.chats]}
        for message in result.messages:
            if isinstance(message, (types.Message, types.MessageService)):
                message._finish_init(self, entities, peer)
        return result.messages


    async def connect(self):
        result = await super().connect()
        if listener := getattr(self, "connection_listener", None):
            listener("opened")
        return result

    def disconnect(self):
        was_connected = self.is_connected()
        result = super().disconnect()
        if was_connected and (listener := getattr(self, "connection_listener", None)):
            listener("closed")
        return result

    @property
    def _request_retries(self):
        return 0 if _single_attempt.get() else self._read_retries

    @_request_retries.setter
    def _request_retries(self, value):
        self._read_retries = value

    async def switch_route(self, options):
        await self.disconnect()
        self._connection = options.get("connection", ConnectionTcpFull)
        self._proxy = options.get("proxy")
        self._init_request.proxy = (types.InputClientProxy(*self._connection.address_info(self._proxy))
                                    if issubclass(self._connection, TcpMTProxy) else None)

    async def _call(self, sender, request, ordered=False, flood_sleep_threshold=None):
        # One outgoing RPC at a time for this authorization, including callers
        # in monitoring's background loops. Resolving a peer may re-enter _call
        # in the same task; that is sequential and must not deadlock.
        if not hasattr(self, "_rpc_lock"):
            self._rpc_lock = asyncio.Lock()
            self._rpc_owner = None
            self._rpc_wait_until = 0
        current = asyncio.current_task()
        if self._rpc_owner is current:
            return await self._serial_call(sender, request, ordered, flood_sleep_threshold)
        async with self._rpc_lock:
            self._rpc_owner = current
            try:
                return await self._serial_call(sender, request, ordered, flood_sleep_threshold)
            finally:
                self._rpc_owner = None

    async def _serial_call(self, sender, request, ordered, flood_sleep_threshold):
        if utils.is_list_like(request):
            return [await self._serial_call(sender, item, ordered, flood_sleep_threshold) for item in request]
        while True:
            stored = getattr(self, "rpc_backoff_getter", lambda: 0)()
            remaining = max(self._rpc_wait_until, stored) - time.time()
            if remaining <= 0:
                break
            await asyncio.sleep(min(remaining, 1))
        single = isinstance(request, _ACTIONS)
        pacer = getattr(self, "bulk_pacer", None)
        paced = pacer is not None and bulk_request(request)
        if paced:
            await pacer.before()
        token = _single_attempt.set(single)
        try:
            result = await super()._call(sender, request, ordered, flood_sleep_threshold)
            if paced:
                pacer.success()
            return result
        except Exception as exc:
            if isinstance(exc, FloodWaitError):
                if pacer is not None:
                    pacer.flooded(exc.seconds)
                self._rpc_wait_until = max(self._rpc_wait_until, time.time() + exc.seconds + 1)
                if save := getattr(self, "rpc_backoff_setter", None):
                    save(self._rpc_wait_until)
            if handler := getattr(self, "rpc_error_handler", None):
                handler(exc)
            raise
        finally:
            _single_attempt.reset(token)
