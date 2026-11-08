import asyncio
import random

from telethon.tl import functions

from .telegram_client import FLOOD_ERRORS


async def post_login(client):
    lang_pack = client.tgwitness_client_profile.get("lang_pack", "")
    requests = [functions.help.GetConfigRequest(), functions.help.GetNearestDcRequest(),
                functions.account.UpdateStatusRequest(offline=False)]
    if lang_pack:
        requests.append(functions.langpack.GetLanguagesRequest(lang_pack=lang_pack))
    requests.extend([functions.help.GetAppUpdateRequest(source=""), functions.help.GetTermsOfServiceUpdateRequest()])
    results = []
    for number, request in enumerate(requests):
        if number:
            await asyncio.sleep(random.uniform(.3, 1.5))
        result = {"request": type(request).__module__.rsplit(".", 1)[-1] + "." + type(request).__name__}
        try:
            await asyncio.wait_for(client(request), 30)
        except Exception as exc:
            result.update(status="failed", error=type(exc).__name__)
            if isinstance(exc, FLOOD_ERRORS):
                result["wait_seconds"] = exc.seconds
            results.append(result)
            break
        results.append({**result, "status": "completed"})
    return results
