import builtins
import logging
import secrets

from telethon import errors

LOG = logging.getLogger("tgwitness.errors")

UNEXPECTED = "An unexpected error stopped this operation. Try again; if it repeats, check the panel log."
DISCONNECTED = "The connection to Telegram broke off. Check the connection route and try again."
SIGNED_OUT = "Telegram no longer recognises this session. Sign in again."
PAUSE = "Telegram asked to pause requests. Wait until the pause ends, then try again."
SPAM_BLOCK = ("Telegram restricts this account from writing to people and chats it has not contacted before "
              "(spam block). Check the account with @SpamBot.")
TEXTS = {
    "AuthKeyDuplicatedError": "Telegram ended this session because it was used in two places at once. Sign in again "
                              "and use the session only in TgWitness.",
    "AuthKeyUnregisteredError": SIGNED_OUT,
    "AuthKeyInvalidError": SIGNED_OUT,
    "AuthKeyError": SIGNED_OUT,
    "SessionRevokedError": "The session was ended from another device or by Telegram. Sign in again.",
    "SessionExpiredError": "Telegram let the session expire. Sign in again.",
    "SessionPasswordNeededError": "This account has a two-step verification password. Enter it to continue.",
    "UnauthorizedError": "Telegram reports this session as signed out. Sign in again.",
    "UserDeactivatedError": "The Telegram account was deleted. Connect another account.",
    "UserDeactivatedBanError": "Telegram banned this account. Connect another account.",
    "FrozenMethodInvalidError": "Telegram froze this account and refuses this request. The account can appeal through "
                                "@SpamBot.",
    "FreshResetAuthorisationForbiddenError": "Telegram lets a session end other sessions only after it has been "
                                             "signed in for 24 hours.",
    "PasswordHashInvalidError": "The two-step verification password is wrong. Enter it again.",
    "PhoneCodeInvalidError": "The login code is wrong. Enter the code from Telegram again.",
    "PhoneCodeExpiredError": "The login code has expired. Request a new code.",
    "PhoneNumberInvalidError": "Telegram does not accept this phone number. Check the country code and the digits.",
    "PhoneNumberBannedError": "Telegram banned this phone number.",
    "ApiIdInvalidError": "Telegram rejected the API ID and API hash. Check them at my.telegram.org.",
    "FloodWaitError": PAUSE,
    "FloodError": PAUSE,
    "SlowModeWaitError": "Slow mode is on in this chat. Wait before sending again.",
    "TakeoutInitDelayError": "Telegram wants this data export confirmed in an official Telegram app. Confirm it there "
                             "and start again after the wait Telegram shows.",
    "TakeoutInvalidError": "Telegram closed the data export session. Start the export again.",
    "PeerFloodError": SPAM_BLOCK,
    "UserBannedInChannelError": SPAM_BLOCK,
    "ChannelPrivateError": "This account cannot open the chat: it is private, or the account was removed or banned "
                           "from it.",
    "ChannelInvalidError": "Telegram does not recognise this chat for this account. Open it from the account's chat "
                           "list.",
    "ChatIdInvalidError": "Telegram does not recognise this chat for this account. Open it from the account's chat "
                          "list.",
    "PeerIdInvalidError": "Telegram does not recognise this chat or person for this account.",
    "ChatAdminRequiredError": "This needs administrator rights in the chat.",
    "ChatWriteForbiddenError": "This account cannot write in this chat.",
    "ChatForbiddenError": "This account has no access to this chat.",
    "UserPrivacyRestrictedError": "This person's privacy settings do not allow it.",
    "MessageIdInvalidError": "Telegram does not have this message for this account.",
    "MsgIdInvalidError": "Telegram does not have this message for this account.",
    "InviteHashExpiredError": "The invite link has expired or was revoked. Ask for a new link.",
    "InviteHashInvalidError": "The invite link is not valid. Check the link.",
    "InviteRequestSentError": "The chat admits new members after approval. The request was sent; wait for an "
                              "administrator.",
    "UserAlreadyParticipantError": "This account is already a member of the chat.",
    "ChannelsTooMuchError": "This account is in too many groups and channels. Leave some before joining another.",
    "UsernameNotOccupiedError": "No chat or person has this username. Check the link.",
    "UsernameInvalidError": "This username is not valid. Check the link.",
    "FileReferenceExpiredError": "Telegram's reference to the file expired. Load the message again and retry.",
    "BotResponseTimeoutError": "The bot did not answer in time. Try again later.",
    "BadRequestError": "Telegram rejected the request. Check the chat or link and try again.",
    "ForbiddenError": "Telegram does not allow this account to do this.",
    "NotFoundError": "Telegram did not find what was requested.",
    "ServerError": "Telegram had an internal problem. Try again in a few minutes.",
    "TimedOutError": "Telegram did not answer in time. Try again in a few minutes.",
    "RPCError": "Telegram rejected the request. Try again; if it repeats, check the account and the chat.",
    "TypeNotFoundError": "Telegram sent data this version of TgWitness cannot read. Update TgWitness.",
    "InvalidBufferError": DISCONNECTED,
    "IncompleteReadError": DISCONNECTED,
    "TimeoutError": "The operation timed out. Check the connection and try again.",
    "ConnectionError": "The connection failed. Check the connection route and try again.",
    "PermissionError": "TgWitness cannot access a file or folder. Check the permissions of the data directory.",
    "FileNotFoundError": "A required file is missing. Check the data directory.",
    "OSError": "A disk or network operation failed. Check free disk space and the connection.",
    "MemoryError": "This computer ran out of memory. Close other programs or choose a smaller range.",
    "UnicodeError": "The file is not in the expected text encoding.",
    "JSONDecodeError": "The data is not valid JSON.",
    "CancelledError": "The operation was cancelled.",
    "Exception": UNEXPECTED,
}
WRITTEN_FOR_PEOPLE = {"ValueError", "Refused", "RouteError", "NoProxyAvailable"}


def describe(exc):
    for kind in type(exc).__mro__:
        if kind.__name__ in WRITTEN_FOR_PEOPLE and str(exc):
            return str(exc)
        if kind.__name__ in TEXTS:
            return TEXTS[kind.__name__]
    return UNEXPECTED


def explain(name):
    kind = getattr(errors, str(name), None) or getattr(builtins, str(name), None)
    if isinstance(kind, type):
        return next((TEXTS[item.__name__] for item in kind.__mro__ if item.__name__ in TEXTS), UNEXPECTED)
    return TEXTS.get(str(name), UNEXPECTED)


def unexpected(exc, where=""):
    error_id = secrets.token_hex(6)
    LOG.error("Error %s in %s", error_id, where or "an operation", exc_info=exc)
    return {"message": UNEXPECTED, "error_id": error_id}
