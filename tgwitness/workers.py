"""Bound background reads and finish file workers before cleanup."""
import asyncio


async def limited_in_thread(slots, function, *args):
    """Keep a read slot until its thread finishes, even if the caller times out."""
    await slots.acquire()
    try:
        task = asyncio.create_task(asyncio.to_thread(function, *args))
    except BaseException:
        slots.release()
        raise

    def finished(worker):
        slots.release()
        if not worker.cancelled():
            worker.exception()

    task.add_done_callback(finished)
    return await asyncio.shield(task)


async def complete_in_thread(function, *args):
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:


        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not task.cancelled():
            task.exception()
        raise
