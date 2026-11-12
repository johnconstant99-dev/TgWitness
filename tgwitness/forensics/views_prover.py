def read_state(before_views, after_views):
    return {"already_viewed": None,
            "views_before": before_views, "views_after": after_views,
            "meaning": "Aggregate post view counters before and after the request."}


async def observe_post_views(client, peer, message_id):
    from telethon.tl.functions.messages import GetMessagesViewsRequest

    before = await client(GetMessagesViewsRequest(peer=peer, id=[message_id], increment=False))
    after = await client(GetMessagesViewsRequest(peer=peer, id=[message_id], increment=False))
    return read_state(before.views[0].views, after.views[0].views)
