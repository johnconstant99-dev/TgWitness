"""Keep retryable reads separate from actions whose outcome may be ambiguous."""
from contextvars import ContextVar

from telethon import TelegramClient, utils
from telethon.tl import functions

_single_attempt = ContextVar("telegram_single_attempt", default=False)
_ACTIONS = (functions.messages.GetBotCallbackAnswerRequest,
            functions.messages.ImportChatInviteRequest, functions.channels.JoinChannelRequest)


class WitnessClient(TelegramClient):
    # Telethon reads this attribute when entering its RPC retry loop. Task-local
    # state avoids changing the policy of concurrent observation/download tasks.
    @property
    def _request_retries(self):
        return 0 if _single_attempt.get() else self._read_retries

    @_request_retries.setter
    def _request_retries(self, value):
        self._read_retries = value

    async def _call(self, sender, request, ordered=False, flood_sleep_threshold=None):
        if utils.is_list_like(request):
            request = list(request)
            single = any(isinstance(r, _ACTIONS) for r in request)
        else:
            single = isinstance(request, _ACTIONS)
        token = _single_attempt.set(single)
        try:
            return await super()._call(sender, request, ordered, flood_sleep_threshold)
        finally:
            _single_attempt.reset(token)
