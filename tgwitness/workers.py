"""Await file workers before their caller cleans up the files they use."""
import asyncio


async def complete_in_thread(function, *args):
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        # Cancelling to_thread does not stop the operating-system thread. Keep
        # its files alive until it exits, including during repeated cancellation.
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not task.cancelled():
            task.exception()  # Consume an error if cancellation and failure raced.
        raise
