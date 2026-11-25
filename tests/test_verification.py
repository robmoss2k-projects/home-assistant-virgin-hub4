"""The shared sequencing has no access to logins or write replay."""

from asyncio import CancelledError, Event, get_running_loop, wait_for
from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest

from custom_components.virgin_hub4 import verification
from custom_components.virgin_hub4.client import CannotConnect, SessionExpired


async def test_single_write_with_lost_ack_and_a_stale_read(monkeypatch):
    wait = AsyncMock()
    monkeypatch.setattr(verification, "sleep", wait)
    write = AsyncMock(side_effect=CannotConnect("synthetic write response was lost"))
    read = AsyncMock(side_effect=["old", CannotConnect("synthetic read failure"), "new"])
    result = await verification.write_and_verify(write, read, lambda value: value == "new")
    assert result.verified and result.latest == "new"
    assert result.reply is None and result.write_issue == "CannotConnect"
    assert read.await_count == 3 and wait.await_count == 3
    assert all(0 <= args.args[0] <= 1 for args in wait.await_args_list)
    write.assert_awaited_once()


async def test_exhaustion_preserves_last_data_and_dhcp_reply(monkeypatch):
    monkeypatch.setattr(verification, "sleep", AsyncMock())
    write = AsyncMock(return_value="vendor status")
    read = AsyncMock(side_effect=["old", SessionExpired("synthetic"), SessionExpired("synthetic")])
    result = await verification.write_and_verify(write, read, lambda value: value == "new")
    assert not result.verified and result.latest == "old"
    assert result.reply == "vendor status" and result.write_issue is None
    write.assert_awaited_once()


async def test_cancelled_caller_is_not_reported_as_a_failed_write():
    write = AsyncMock(side_effect=CancelledError)
    read = AsyncMock()
    with pytest.raises(CancelledError):
        await verification.write_and_verify(write, read, lambda _: True)
    write.assert_awaited_once()
    read.assert_not_awaited()


async def test_definitely_expired_write_never_reads_someone_elses_session():
    write = AsyncMock(side_effect=SessionExpired("expired during submission"))
    read = AsyncMock(return_value="new")
    result = await verification.write_and_verify(write, read, lambda value: value == "new")
    assert not result.verified and result.latest is None
    assert result.write_issue == "SessionExpired"
    write.assert_awaited_once()
    read.assert_not_awaited()


async def test_default_accepts_a_write_that_settles_after_a_minute(monkeypatch):
    elapsed = 0.0
    start = get_running_loop().time()

    async def tick(seconds):
        nonlocal elapsed
        elapsed += seconds

    monkeypatch.setattr(
        verification, "get_running_loop", lambda: SimpleNamespace(time=lambda: start + elapsed)
    )
    monkeypatch.setattr(verification, "sleep", tick)
    write = AsyncMock(side_effect=CannotConnect("lost write response"))
    read = AsyncMock(side_effect=lambda: "new" if elapsed >= 90 else "old")

    result = await verification.write_and_verify(write, read, lambda value: value == "new")

    assert result.verified and 90 <= elapsed < 92
    assert result.write_issue == "CannotConnect"
    write.assert_awaited_once()


async def test_poll_mode_reads_past_the_three_short_attempts_without_replaying(monkeypatch):
    monkeypatch.setattr(verification, "sleep", AsyncMock())
    write = AsyncMock(side_effect=CannotConnect("lost write response"))
    read = AsyncMock(side_effect=["old", "old", CannotConnect("busy"), "old", "new"])
    result = await verification.write_and_verify(
        write, read, lambda value: value == "new", poll_seconds=60
    )
    assert result.verified and result.latest == "new" and result.write_issue == "CannotConnect"
    assert read.await_count == 5
    write.assert_awaited_once()


async def test_poll_stops_on_an_expired_session_and_keeps_last_good_sample(monkeypatch):
    monkeypatch.setattr(verification, "sleep", AsyncMock())
    write = AsyncMock()
    read = AsyncMock(side_effect=["old", SessionExpired("session ended"), "new"])
    result = await verification.write_and_verify(
        write, read, lambda value: value == "new", poll_seconds=60
    )
    assert not result.verified and result.latest == "old"
    assert read.await_count == 2
    write.assert_awaited_once()


async def test_poll_deadline_bounds_stalled_reads_and_allows_one_final_sample(monkeypatch):
    monkeypatch.setattr(verification, "_FINAL_READ_SECONDS", 0.01)
    write = AsyncMock()
    read = AsyncMock(side_effect=Event().wait)
    result = await wait_for(
        verification.write_and_verify(write, read, lambda _: True, poll_seconds=0.01), 0.5
    )
    assert not result.verified and result.latest is None
    assert read.await_count == 2
    write.assert_awaited_once()
