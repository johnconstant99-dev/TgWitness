import asyncio
import time

from telethon.tl import functions, types
from telethon.tl.alltlobjects import LAYER

from . import client_identity, client_profiles
from .store import utcnow
from .telegram_client import FLOOD_ERRORS


async def inspect_connection(client):
    profile = client.tgwitness_client_profile
    init = getattr(client, "_init_request", None)
    api_id = getattr(init, "api_id", None) or getattr(client, "api_id", None)
    baseline = client_profiles.catalog()["platforms"]["layer"]
    report = {"checked_at": utcnow(), "source": "telegram_api", "official_app": None, "checks": []}
    requests = [("get_config", functions.help.GetConfigRequest()),
                ("nearest_dc", functions.help.GetNearestDcRequest()),
                ("current_session", functions.account.GetAuthorizationsRequest()),
                ("layer_match", None),
                ("lang_pack", functions.langpack.GetLanguagesRequest(lang_pack=profile["lang_pack"]) if profile["lang_pack"] else None),
                ("app_update", functions.help.GetAppUpdateRequest(source="")),
                ("terms_of_service", functions.help.GetTermsOfServiceUpdateRequest())]
    stopped, sent = False, False
    for name, request in requests:
        check = {"name": name}
        if request is None:
            if name == "layer_match":
                check.update(status="ok" if LAYER == baseline else "warning", actual=LAYER, baseline=baseline,
                             detail="The baseline is a reviewed snapshot, not Telegram's latest required layer.")
            else:
                check.update(status="ok", detail="Empty language pack retained; no language-list request.")
        elif stopped or getattr(client, "rpc_backoff_getter", lambda: 0)() > time.time():
            check.update(status="skipped", detail="Requests stopped after an error or while Telegram requires a wait.")
        else:
            if sent:
                await asyncio.sleep(.3)
            sent = True
            try:
                response = await asyncio.wait_for(client(request), 30)
                check["status"] = "ok"
                if name == "get_config":
                    check["dc_id"] = response.this_dc
                elif name == "nearest_dc":
                    check.update(dc_id=response.this_dc, nearest_dc=response.nearest_dc)
                elif name == "current_session":
                    current = next((a for a in response.authorizations if a.current), None)
                    if current is None:
                        check.update(status="warning", detail="Telegram did not identify a current authorization.")
                    else:
                        report["official_app"] = bool(current.official_app)
                        report["authorization"] = {key: getattr(current, key) for key in (
                            "api_id", "device_model", "platform", "system_version", "app_name", "app_version")}
                        check.update(status="ok" if current.official_app else "warning",
                                     official_app=bool(current.official_app),
                                     detail="Telegram's official-app flag is not an account-safety assessment.")
                elif name == "lang_pack":
                    check.update(lang_pack=profile["lang_pack"], languages=len(response))
                elif name == "app_update":
                    check["update_available"] = isinstance(response, types.help.AppUpdate)
                    if check["update_available"]:
                        check["version"] = response.version
                elif name == "terms_of_service":
                    check["update_available"] = isinstance(response, types.help.TermsOfServiceUpdate)
            except Exception as exc:
                check.update(status="failed", error=type(exc).__name__)
                if isinstance(exc, FLOOD_ERRORS):
                    check["wait_seconds"] = exc.seconds
                stopped = True
        report["checks"].append(check)
    report["warnings"] = client_identity.consistency_warnings(api_id, profile, LAYER)
    return report
