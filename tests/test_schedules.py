"""Offline tests for the distinct schedule formats used by the portal."""

import json
from unittest.mock import AsyncMock

import pytest

from custom_components.virgin_hub4.client import HubClient, InvalidResponse
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from custom_components.virgin_hub4.schedules import decode_schedule, plan_schedule
from test_client import FakeHttp, LOGIN, MODE

MAC_ALWAYS = {"blockTimeType": "Always", "timeSchedules": "F" * 42 + "7F"}
IP_ALWAYS = {"blockTimeType": 0, "timeSchedules": [2147483647] * 7}


def test_ip_always_uses_the_portals_string_value():
    wire, state = plan_schedule({"mode": "always"}, ip=True)
    assert wire == {"timeSchedules": "2147483647", "foralldays": False}
    assert decode_schedule(IP_ALWAYS, ip=True) == state


def test_daily_at_midnight_boundaries():
    proposed = {"mode": "daily", "periods": [{"start": 23, "end": 24}, {"start": 0, "end": 1}]}
    mac, canonical = plan_schedule(proposed, ip=False)
    assert mac == {"blockTimeType": "ByHour", "timeSchedules": "0" * 36 + "8000017f"}
    assert canonical["periods"] == list(reversed(proposed["periods"]))
    assert decode_schedule(mac, ip=False) == canonical
    ip, _ = plan_schedule(proposed, ip=True)
    assert ip == {"timeSchedules": 1073742079, "foralldays": False}
    assert (
        decode_schedule({"blockTimeType": 1, "timeSchedules": [1073742079]}, ip=True) == canonical
    )


def test_daily_ip_readback_can_repeat_hours_without_day_bits():
    request = {"mode": "daily", "periods": [{"start": 1, "end": 2}, {"start": 6, "end": 8}]}
    wire, expected = plan_schedule(request, ip=True)
    assert wire["timeSchedules"] == 24959
    assert decode_schedule({"blockTimeType": 1, "timeSchedules": [24832] * 7}, ip=True) == expected
    with pytest.raises(InvalidResponse, match="invalid daily"):
        decode_schedule({"blockTimeType": 1, "timeSchedules": [24832] * 6 + [0]}, ip=True)


@pytest.mark.parametrize("ip", (False, True))
@pytest.mark.asyncio
async def test_weekly_authenticated_write_and_readback(ip):
    request = {
        "mode": "weekly",
        "periods": [
            {"day": "mon", "start": 1, "end": 3},
            {"day": "mon", "start": 2, "end": 4},
            {"day": "sun", "start": 23, "end": 24},
        ],
    }
    if ip:
        before = IP_ALWAYS
        expected = {"timeSchedules": [1073741825, 1794, 0, 0, 0, 0, 0], "foralldays": True}
        after = {"blockTimeType": "2", "timeSchedules": expected["timeSchedules"]}
    else:
        before = MAC_ALWAYS
        expected = {"blockTimeType": "ByDayHour", "timeSchedules": "0" * 30 + "00000e80000003"}
        after = expected | {"timeSchedules": expected["timeSchedules"].upper()}
    http = FakeHttp(MODE, LOGIN, json.dumps(before), "1", json.dumps(after), "")
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    prefix = "ip" if ip else "mac"
    group = f"{prefix}_filter_schedule"
    result = await apply_owned_session(hub, group, request)
    assert await hub.logout()
    assert result == {
        "status": "verified",
        "group": group,
        "readback": {
            "mode": "weekly",
            "periods": [
                {"day": "mon", "start": 1, "end": 4},
                {"day": "sun", "start": 23, "end": 24},
            ],
        },
    }
    path, options = http.requests[3]
    assert path == f"/php/{prefix}_blocktime.php"
    assert options["data"]["opType"] == "WRITE"
    assert json.loads(options["data"]["blockTimeData"]) == expected


@pytest.mark.asyncio
async def test_no_write_on_bad_period_or_unreadable_current_state():
    hub = AsyncMock()
    hub.read_schedule.return_value = MAC_ALWAYS
    group = "mac_filter_schedule"
    result = await apply_owned_session(hub, group, {"mode": "always"})
    assert result["status"] == "unchanged"
    with pytest.raises(InvalidSetting, match="whole hours"):
        await apply_owned_session(
            hub, group, {"mode": "daily", "periods": [{"start": 6, "end": 5}]}
        )
    hub.read_schedule.return_value = {"blockTimeType": "ByDayHour", "timeSchedules": "0" * 44}
    with pytest.raises(InvalidResponse, match="invalid weekly"):
        await apply_owned_session(hub, group, {"mode": "always"})
    hub.write_schedule.assert_not_awaited()


@pytest.mark.asyncio
async def test_no_replay_or_confirmation_for_unapplied_schedule(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    hub = AsyncMock()
    hub.read_schedule.return_value = IP_ALWAYS
    result = await apply_owned_session(
        hub, "ip_filter_schedule", {"mode": "daily", "periods": [{"start": 3, "end": 4}]}
    )
    assert result["status"] == "unverified"
    hub.write_schedule.assert_awaited_once()
