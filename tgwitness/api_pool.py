"""Built-in Telegram API pairs, used only when a workspace has no pair of its own."""
import random

from telethon.errors import ApiIdInvalidError, ApiIdPublishedFloodError, UpdateAppToLoginError

# Public application pairs: none entered, none saved and none supplied by an imported account file.
POOL = (
    (2040, "b18441a1ff607e10a989891a5462e627"), (800812, "db55ad67a98df35667ca788b97f771f5"),
    (27097807, "9fd790a9cb1f639c921d941621d2959d"), (1621727, "31350903c528876f79527398c09660ce"),
    (17349, "344583e45741c457fe1862106095a5eb"), (24872155, "36560cde182f779d6fe129dcd1d8f527"),
    (25790571, "2b95fb1f6f630a83e0712e84ddb337f2"), (1652138, "b2f0d235e8f8d7f4d6a11a39058aef55"),
    (7391573, "1f20df54dfd91bcee05278d3b01da2c7"), (19358020, "de33bd71c8d49212c32af0bc10d67617"),
    (25472096, "6aefac26bd80dc0a1088ca14cb67be66"), (3420052, "ec130bf6eb5a4b0710e6e989cbb7dd28"),
    (10608382, "ea04136e7acb517f48ccf8425ca99243"), (27598177, "2a17655facad0790ca4ceb626ef23feb"),
    (107649, "4c0cbb403eb99d14e4ba38a4e40c2e13"), (29987885, "38e7dccee55f49d40a5a5a7e08549442"),
    (1025907, "452b0359b988148995f22ff0f4229750"), (29848011, "ab9bd73716cfe9939ea5ff0bd9bad498"),
    (26487396, "778b12cba913e98ee54b5ee441b908c9"), (29755247, "8dd9fb5fa2782d91b9847ace66eb885a"),
    (28166206, "22c2ee7d72e541da8f35ad8e00b16315"), (29510141, "14c074a5aed49dc7752a9f8d54cf4ad4"),
    (28925121, "667bf87d3ce77e3e9f5bc4e62021c152"), (314338, "dfdae44a7ccfa24eed4326d54c1e31a5"),
    (25221873, "6b9b455b58e19a006eb8ed906c84b370"), (27765349, "9df1f705c8047ac0d723b29069a1332b"),
    (26365804, "311437f18ff014a3689409c9eeb44d42"), (28059844, "7ef57d924f83752e18736e32d2fcd7f1"),
    (20261016, "23240f2a7b2e08a801e8a5b3d787fc9e"), (20126690, "3ea37bd78cb3a8ca92caac7a23b542d9"),
    (10953300, "9c24426e5d6fa1d441913e3906627f87"), (29459757, "7cc969764c4de8a52169570ac20000a8"),
    (25590804, "7c263991b86aecab2a9f5963a399997d"), (15278307, "e2cb1c09f6899dcf30f7cac503495d90"),
    (28418618, "993aded4010f0bdf844dc777859516b8"), (20249833, "4d8a602fa4581d86666033e8a1b5cd28"),
    (23877053, "989c360358b981dae46a910693ab2f4c"), (14688437, "5310285db722d1dceb128b88772d53a6"),
    (22340540, "264130c425cb6a107c99fa8c4155a078"), (835539, "b7e58eaa5a0f75ef422c75d64574551c"),
    (26675200, "9773b9c1900d5b47bd4d20a985f539b6"), (13469730, "f2bb2d8a1d1f9f235bcf742b2d04f93e"),
    (19691895, "93e64ab1fca196717682f11b879b9214"), (23652918, "fdfefb9dde5b0edd59d349b64901dc3a"),
    (10247139, "96b46175824223a33737657ab943fd6a"), (24308228, "afcfde8b88be218303a7e2975bee8e63"),
    (21968589, "b7270cc2655ab46c60fca0abc005cd96"), (441946, "927ac3db15d4f533830abd64efabe261"),
    (11405252, "b1a1fc3dc52ccc91781f33522255a880"), (20522778, "abebb47e89c3f4fd7dae544a72cd00bc"),
)
POOL_IDS = frozenset(api_id for api_id, _ in POOL)
DESKTOP_ID = 2040
# Client description sent with the Telegram Desktop pair, consistent with the application it identifies.
DESKTOP_DEVICE = {"device_model": "Desktop", "system_version": "Windows 10", "app_version": "5.6.3 x64",
                  "lang_code": "en", "system_lang_code": "en-US"}
# Telegram refuses the application itself; another pair may still work for the same login.
PAIR_ERRORS = (ApiIdInvalidError, ApiIdPublishedFloodError, UpdateAppToLoginError)
# Pairs tried per login, so one sign-in never cycles through the whole pool against Telegram.
ATTEMPTS = 8
rejected = set()


def login_order(first=None):
    """Pairs for one login: a previously used pool pair first, then the rest in random order."""
    pairs = [pair for pair in POOL if pair[0] not in rejected and pair != first]
    random.shuffle(pairs)
    if first in POOL and first[0] not in rejected:
        pairs.insert(0, first)
    return (pairs or list(POOL))[:ATTEMPTS]


def reject(api_id):
    if api_id in POOL_IDS:
        rejected.add(api_id)
