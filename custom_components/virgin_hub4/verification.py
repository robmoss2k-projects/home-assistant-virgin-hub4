"""Read back reversible writes without resending them or changing session."""

from __future__ import annotations

from asyncio import get_running_loop, sleep, timeout_at
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

from .client import HubError, SessionExpired

_POLL_INTERVAL = 1.0
_FINAL_READ_SECONDS = 5.0
READBACK_SECONDS = 120


@dataclass(frozen=True, repr=False)
class Readback[State, Reply]:
    verified: bool
    latest: State | None
    reply: Reply | None
    write_issue: str | None


async def readback_samples[State](
    read: Callable[[], Awaitable[State | None]],
    *,
    poll_seconds: float | None = None,
    interval: float = _POLL_INTERVAL,
    first_delay: float = 0,
) -> AsyncIterator[State]:
    clock = get_running_loop().time
    start = clock()
    deadline = start + (READBACK_SECONDS if poll_seconds is None else poll_seconds)
    due = min(deadline, start + first_delay)
    while True:
        await sleep(max(0, due - clock()))
        started = clock()
        final = due >= deadline or started >= deadline
        budget = started + _FINAL_READ_SECONDS if final else deadline
        try:
            async with timeout_at(budget):
                value = await read()
        except SessionExpired:
            return
        except HubError, TimeoutError:
            pass
        else:
            if value is not None:
                yield value
        if final:
            return
        due = min(deadline, started + interval)


async def write_and_verify[State, Reply](
    write: Callable[[], Awaitable[Reply]],
    read: Callable[[], Awaitable[State | None]],
    matches: Callable[[State], bool],
    *,
    poll_seconds: float | None = None,
    reject_reply: Callable[[Reply], bool] | None = None,
) -> Readback[State, Reply]:
    """Attempt one write, then read only on the caller's existing session."""
    reply = write_issue = None
    try:
        reply = await write()
    except SessionExpired:
        # A definite loss of session is not a lost transport acknowledgement.
        # Do not try to verify against data from a session we no longer own.
        return Readback(False, None, None, "SessionExpired")
    except HubError as exc:
        # A lost response is not proof the write failed. Never replay it.
        write_issue = type(exc).__name__
    else:
        if reject_reply is not None and reject_reply(reply):
            return Readback(False, None, reply, None)
    latest = None
    async for latest in readback_samples(read, poll_seconds=poll_seconds):
        if matches(latest):
            return Readback(True, latest, reply, write_issue)
    return Readback(False, latest, reply, write_issue)
