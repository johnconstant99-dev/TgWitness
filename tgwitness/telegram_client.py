from contextvars import ContextVar

from telethon import TelegramClient, utils
from telethon.network.connection import ConnectionTcpFull
from telethon.network.connection.tcpmtproxy import TcpMTProxy
from telethon.tl import functions, types

_single_attempt = ContextVar("telegram_single_attempt", default=False)
_ACTIONS = (functions.messages.GetBotCallbackAnswerRequest,
            functions.messages.ImportChatInviteRequest, functions.channels.JoinChannelRequest)


class WitnessClient(TelegramClient):


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
        if utils.is_list_like(request):
            request = list(request)
            single = any(isinstance(r, _ACTIONS) for r in request)
        else:
            single = isinstance(request, _ACTIONS)
        token = _single_attempt.set(single)
        try:
            return await super()._call(sender, request, ordered, flood_sleep_threshold)
        except Exception as exc:
            if handler := getattr(self, "rpc_error_handler", None):
                handler(exc)
            raise
        finally:
            _single_attempt.reset(token)
