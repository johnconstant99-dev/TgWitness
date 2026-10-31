"""Buttons under a message, read from the saved Telegram object (payload raw.reply_markup).

Bots hand out links, web apps and texts to copy through buttons rather than message text.
Reading them from the saved object works for records made before this module existed too.
Older Telegram layers name each button by its class (KeyboardButtonUrl); newer ones use one
button class with a type object (KeyboardInlineButton with InlineButtonTypeUrl). Both are read.
"""
TYPES = {

    "InlineButtonTypeUrl": "url", "InlineButtonTypeCallback": "callback", "InlineButtonTypeCopy": "copy",
    "InlineButtonTypeSwitchInline": "switch_inline", "InlineButtonTypeUrlAuth": "login_url",
    "InlineButtonTypeUserProfile": "user_profile", "InlineButtonTypeWebView": "web_app", "InlineButtonTypeGame": "game",
    "InlineButtonTypeBuy": "buy", "InlineButtonTypeDisabled": "disabled", "ButtonTypeDefault": "text",
    "ButtonTypeRequestPhone": "request_phone", "ButtonTypeRequestGeoLocation": "request_location",
    "ButtonTypeRequestPeer": "request_chat", "ButtonTypeRequestPoll": "request_poll", "ButtonTypeSimpleWebView": "web_app",

    "KeyboardButton": "text", "KeyboardButtonUrl": "url", "KeyboardButtonCallback": "callback",
    "KeyboardButtonUrlAuth": "login_url", "KeyboardButtonWebView": "web_app", "KeyboardButtonSimpleWebView": "web_app",
    "KeyboardButtonSwitchInline": "switch_inline", "KeyboardButtonRequestPhone": "request_phone",
    "KeyboardButtonRequestGeoLocation": "request_location", "KeyboardButtonRequestPoll": "request_poll",
    "KeyboardButtonRequestPeer": "request_chat", "InputKeyboardButtonRequestPeer": "request_chat",
    "KeyboardButtonUserProfile": "user_profile", "InputKeyboardButtonUserProfile": "user_profile",
    "KeyboardButtonGame": "game", "KeyboardButtonBuy": "buy", "KeyboardButtonCopy": "copy",
}
FIELDS = ("url", "query", "copy_text", "user_id", "fwd_text")


def keyboard(markup):
    """{"inline": bool, "rows": [[{type, text, url?, query?, copy_text?, data_base64?}]]} or None.

    markup is the plain-dict form of a Telegram reply markup, as saved in raw.reply_markup.
    """
    if not isinstance(markup, dict):
        return None
    rows = []
    for row in markup.get("rows") or []:
        items = []
        for button in (row or {}).get("buttons") or []:
            details = button.get("type") if isinstance(button.get("type"), dict) else button
            name = details.get("_", "")
            item = {"type": TYPES.get(name, name), "text": button.get("text") or ""}
            for field in FIELDS:
                if details.get(field) not in (None, ""):
                    item[field] = details[field]
            data = details.get("data")
            if isinstance(data, dict) and data.get("bytes_base64"):
                item["data_base64"] = data["bytes_base64"]
            items.append(item)
        if items:
            rows.append(items)
    if not rows:
        return None
    return {"inline": markup.get("_") == "ReplyInlineMarkup", "rows": rows}


def of_payload(payload):
    return keyboard(((payload or {}).get("raw") or {}).get("reply_markup"))
