import asyncio
import copy
import logging
import time
from contextvars import ContextVar

from telethon import TelegramClient, utils
from telethon.errors import FloodWaitError, FloodPremiumWaitError
from telethon.network.connection import ConnectionTcpObfuscated
from telethon.network.connection.tcpmtproxy import TcpMTProxy
from telethon.tl import functions, types
from telethon.tl.tlobject import TLRequest

from .rpc_pacing import bulk_request

_single_attempt = ContextVar("telegram_single_attempt", default=False)
LOG = logging.getLogger("tgwitness.telegram_client")

try:
    from telethon._updates.messagebox import ENTRY_ACCOUNT, MessageBox
except ImportError:
    MessageBox = None


if MessageBox is not None:
    class GapAwareMessageBox(MessageBox):
        __slots__ = ("gap_owner",)

        def apply_difference(self, diff, chat_hashes):
            if isinstance(diff, types.updates.DifferenceTooLong):
                self.report_gap(None, ENTRY_ACCOUNT, diff.pts)
            return super().apply_difference(diff, chat_hashes)

        def apply_channel_difference(self, request, diff, chat_hashes):
            if isinstance(diff, types.updates.ChannelDifferenceTooLong):
                entry = request.channel.channel_id
                self.report_gap(entry, entry, getattr(diff.dialog, "pts", None))
            return super().apply_channel_difference(request, diff, chat_hashes)

        def report_gap(self, channel_id, entry, after):
            owner = getattr(self, "gap_owner", None)
            if owner is not None:
                owner.difference_gap(channel_id, getattr(self.map.get(entry), "pts", None), after)
else:
    GapAwareMessageBox = None
FLOOD_ERRORS = (FloodWaitError, FloodPremiumWaitError)
_ACTIONS = (functions.messages.GetBotCallbackAnswerRequest,
            functions.messages.ImportChatInviteRequest, functions.channels.JoinChannelRequest,
            functions.auth.AcceptLoginTokenRequest)
_READ_RECEIPTS = (functions.messages.ReadHistoryRequest, functions.messages.ReadMessageContentsRequest,
                  functions.channels.ReadHistoryRequest, functions.channels.ReadMessageContentsRequest,
                  functions.messages.ReadDiscussionRequest, functions.messages.ReadMentionsRequest,
                  functions.messages.ReadReactionsRequest, functions.messages.ReadEncryptedHistoryRequest,
                  functions.stories.ReadStoriesRequest)
_OWN_UPDATES = (types.messages.AffectedMessages, types.messages.AffectedHistory, types.messages.AffectedFoundMessages)


def method_name(request):
    while isinstance(getattr(request, "query", None), TLRequest):
        request = request.query
    name = type(request).__name__.removesuffix("Request")
    group = type(request).__module__.rpartition(".")[2]
    return ("" if group == "functions" else group + ".") + name[:1].lower() + name[1:]


class ReadReceiptBlocked(ValueError):
    pass


def reject_read_receipts(request):
    pending = [request]
    while pending:
        item = pending.pop()
        if utils.is_list_like(item):
            pending.extend(item)
        elif isinstance(item, _READ_RECEIPTS):
            raise ReadReceiptBlocked("Read receipts are disabled in the TgWitness API collector.")
        elif (query := getattr(item, "query", None)) is not None:
            pending.append(query)


def request_method(request):
    wrappers = (functions.InvokeWithTakeoutRequest, functions.InvokeWithMessagesRangeRequest,
                functions.InvokeWithLayerRequest, functions.InitConnectionRequest)
    names = []
    for _ in range(8):
        cls = type(request)
        prefix = "telethon.tl.functions"
        if cls.__module__ != prefix and not cls.__module__.startswith(prefix + "."):
            names.append("unknown")
            break
        namespace = cls.__module__[len(prefix):].strip(".")
        name = cls.__name__.removesuffix("Request")
        names.append((namespace + "." if namespace else "") + name[:1].lower() + name[1:])
        if not isinstance(request, wrappers):
            break
        request = request.query
    return {"method": names[-1], "wrappers": names[:-1]}


class WitnessClient(TelegramClient):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if GapAwareMessageBox is not None:
            box = GapAwareMessageBox(self._log["messagebox"])
            box.gap_owner = self
            self._message_box = box

    def difference_gap(self, channel_id, before, after):
        if listener := getattr(self, "difference_gap_listener", None):
            try:
                listener(channel_id, before, after)
            except Exception:
                LOG.exception("Recording an undelivered update interval failed")

    async def history_page(self, entity, *, limit, offset_id):
        peer = await self.get_input_entity(entity)
        result = await self(functions.messages.GetHistoryRequest(peer, offset_id, None, 0, limit, 0, 0, 0))
        entities = {utils.get_peer_id(item): item for item in [*result.users, *result.chats]}
        for message in result.messages:
            if isinstance(message, (types.Message, types.MessageService)):
                message._finish_init(self, entities, peer)
        return result.messages

    def rpc_activity(self):
        return copy.deepcopy(getattr(self, "_rpc_activity", None))

    async def connect(self):
        from .client_identity import apply_init_params
        apply_init_params(self)
        self._connection_cleanup_pending = True
        result = await super().connect()
        if listener := getattr(self, "connection_listener", None):
            listener("opened")
        return result

    async def _disconnect_coro(self):
        pending = self.is_connected() or getattr(self, "_connection_cleanup_pending", False)
        try:
            return await super()._disconnect_coro()
        finally:
            if pending and not self.is_connected():
                self._connection_cleanup_pending = False
                if listener := getattr(self, "connection_listener", None):
                    listener("closed")

    async def _handle_auto_reconnect(self):
        await super()._handle_auto_reconnect()
        if listener := getattr(self, "connection_listener", None):
            listener("reconnected")

    @property
    def _request_retries(self):
        return 0 if _single_attempt.get() else self._read_retries

    @_request_retries.setter
    def _request_retries(self, value):
        self._read_retries = value

    async def switch_route(self, options):
        await self.disconnect()
        self._connection = options.get("connection", ConnectionTcpObfuscated)
        self._proxy = options.get("proxy")
        self._init_request.proxy = (types.InputClientProxy(*self._connection.address_info(self._proxy))
                                    if issubclass(self._connection, TcpMTProxy) else None)

    async def _call(self, sender, request, ordered=False, flood_sleep_threshold=None):
        if utils.is_list_like(request):
            request = tuple(request)
        reject_read_receipts(request)
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
        info = request_method(request)
        if not hasattr(self, "_rpc_activity"):
            self._rpc_activity = {"since": time.time(), "methods": {}}
        key = "/".join([*info["wrappers"], info["method"]])
        counts = self._rpc_activity["methods"].setdefault(key,
            {"calls": 0, "ok": 0, "errors": 0, "cancelled": 0, "flood_waits": 0})
        counts["calls"] += 1
        try:
            result = await super()._call(sender, request, ordered, flood_sleep_threshold)
            if paced:
                pacer.success()
            counts["ok"] += 1
            if (isinstance(result, _OWN_UPDATES) or getattr(result, "SUBCLASS_OF_ID", None) == types.Updates.SUBCLASS_OF_ID) \
                    and (listener := getattr(self, "updates_listener", None)):
                listener()
            return result
        except asyncio.CancelledError:
            counts["cancelled"] += 1
            raise
        except Exception as exc:
            counts["errors"] += 1
            if isinstance(exc, FLOOD_ERRORS):
                if pacer is not None:
                    pacer.flooded(exc.seconds)
                counts["flood_waits"] += 1
                self._rpc_wait_until = max(self._rpc_wait_until,
                    getattr(self, "rpc_backoff_getter", lambda: 0)(), time.time() + exc.seconds + 1)
                if save := getattr(self, "rpc_backoff_setter", None):
                    save(self._rpc_wait_until, method_name(request))
                if observe := getattr(self, "rpc_backoff_observer", None):
                    failed = getattr(exc, "request", None)
                    observe({**info, "failed_method": request_method(failed)["method"] if failed is not None else info["method"],
                             "error_type": type(exc).__name__, "retry_after_seconds": exc.seconds,
                             "wait_until": self._rpc_wait_until, "observed_at": time.time(),
                             "activity": self.rpc_activity()})
            if handler := getattr(self, "rpc_error_handler", None):
                handler(exc)
            raise
        finally:
            _single_attempt.reset(token)
