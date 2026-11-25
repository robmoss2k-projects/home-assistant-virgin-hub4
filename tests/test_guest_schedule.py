"""Offline checks for the guest wizard timer and passphrase invariants."""

from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock

import pytest

from custom_components.virgin_hub4.client import CannotConnect, HubClient, SessionCrypto
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from custom_components.virgin_hub4.guest_schedule import _requested_expiry
from test_client import FakeHttp, LOGIN, MODE, RADIOS, encrypted_reply, fixture_hub

KEY = "synthetic-guest-key"
WIFI = {
    "enable": "1",
    "ssid": "Fixture Guest",
    "broadcast": "1",
    "security": "4",
    "passphrase": KEY,
    "24Passphrase": "synthetic-primary-24-key",
    "50Passphrase": "synthetic-primary-50-key",
}
TIMER = {
    "EnableGuest": "true",
    "NetworkName": "Fixture Guest",
    "GuestWizPassphrase": KEY,
    "ActiveTimeout": "",
}


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr(
        "custom_components.virgin_hub4.guest_schedule._now",
        lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_exact_auth_wire_and_fresh_expiry_readback():
    http = FakeHttp(
        MODE,
        LOGIN,
        encrypted_reply(TIMER),
        encrypted_reply(WIFI),
        RADIOS,
        '"OK"',
        encrypted_reply(TIMER | {"ActiveTimeout": "24/11/2026-18:30"}),
        encrypted_reply(WIFI),
        "",
    )
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    reply = await apply_owned_session(
        hub,
        "guest_schedule",
        {"mode": "until", "expires_at": "2026-11-24 18:30"},
    )
    assert await hub.logout()
    assert reply == {
        "status": "recorded",
        "network_name": "Fixture Guest",
        "expires_at": "2026-11-24T18:30",
        "enabled": True,
        "expiry_enforcement_verified": False,
    }
    path, request = http.requests[5]
    assert path == "/php/wifi_data.php" and request["data"]["opType"] == "WRITE"
    envelope = json.loads(request["data"]["wifiData"])
    setup = json.loads(http.requests[1][1]["data"]["configInfo"])
    assert setup["iv"] != envelope["iv"]
    crypto = SessionCrypto.from_password("fixture-pass", salt=setup["salt"])
    fields = crypto.open_response(envelope, envelope)
    assert fields["csrf_nonce"] == request["headers"]["CSRF_NONCE"]
    for key in ("authData", "salt", "iv", "csrf_nonce"):
        fields.pop(key)
    assert fields == {
        "EnableGuest": "true",
        "NetworkName": "Fixture Guest",
        "GuestWizPassphrase": KEY,
        "GuestTimeBased": True,
        "timeout": 0,
        "yr": 2026,
        "mnt": 11,
        "dy": 24,
        "hr": 18,
        "min": 30,
    }


@pytest.mark.asyncio
async def test_clear_dated_expiry_without_inventing_date_fields():
    hub = fixture_hub()
    hub.read_wifi.side_effect = [TIMER | {"ActiveTimeout": "24/11/2026-18:30"}, WIFI, TIMER, WIFI]
    assert (await apply_owned_session(hub, "guest_schedule", {"mode": "always"}))[
        "status"
    ] == "recorded"
    hub.write_guest_schedule.assert_awaited_once_with(
        {
            "EnableGuest": "true",
            "NetworkName": "Fixture Guest",
            "GuestWizPassphrase": KEY,
            "GuestTimeBased": False,
            "timeout": 0,
            "yr": 0,
        }
    )


@pytest.mark.asyncio
async def test_wont_silently_enable_wifi_or_copy_a_different_guest_key():
    hub = fixture_hub()
    hub.read_wifi.side_effect = [
        TIMER | {"EnableGuest": "false"},
        WIFI | {"enable": "0"},
        TIMER,
        WIFI | {"passphrase": "different-fixture-key"},
    ]
    request = {"mode": "until", "expires_at": "2026-11-24 18:30"}
    with pytest.raises(InvalidSetting, match="allow that explicitly"):
        await apply_owned_session(hub, "guest_schedule", request)
    with pytest.raises(InvalidSetting, match="existing passphrases"):
        await apply_owned_session(hub, "guest_schedule", request)
    hub.write_guest_schedule.assert_not_awaited()


@pytest.mark.parametrize("old_key", ["", "********", "different-synthetic"])
async def test_explicit_wizard_key_can_enable_a_network_without_a_usable_old_key(old_key):
    hub = fixture_hub()
    new_key = "FirstGuestKey43!"
    hub.read_wifi.side_effect = [
        TIMER | {"EnableGuest": "false", "GuestWizPassphrase": ""},
        WIFI | {"enable": "0", "passphrase": old_key},
        TIMER | {"GuestWizPassphrase": new_key},
        WIFI | {"passphrase": new_key},
    ]
    result = await apply_owned_session(
        hub, "guest_schedule", {"mode": "always", "enable_if_off": True, "passphrase": new_key}
    )
    assert result["status"] == "recorded" and result["enabled"]
    assert new_key not in repr(result)
    hub.write_guest_schedule.assert_awaited_once()
    assert hub.write_guest_schedule.await_args.args[0]["GuestWizPassphrase"] == new_key


async def test_explicit_wizard_key_requires_agreement_before_reporting_noop():
    hub = fixture_hub()
    chosen = "AgreedGuestKey1!"
    hub.read_wifi.side_effect = [
        TIMER | {"GuestWizPassphrase": chosen},
        WIFI,
        TIMER | {"GuestWizPassphrase": chosen},
        WIFI | {"passphrase": chosen},
    ]
    reply = await apply_owned_session(
        hub, "guest_schedule", {"mode": "always", "passphrase": chosen}
    )
    assert reply["status"] == "recorded"
    hub.write_guest_schedule.assert_awaited_once()


@pytest.mark.asyncio
async def test_late_timer_readback_does_not_replay_the_write(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.sleep", AsyncMock())
    hub = fixture_hub()
    hub.write_guest_schedule.side_effect = CannotConnect("lost write response")
    hub.read_wifi.side_effect = [TIMER, WIFI] * 5 + [
        TIMER | {"ActiveTimeout": "24/11/2026-18:30"},
        WIFI,
    ]
    result = await apply_owned_session(
        hub, "guest_schedule", {"mode": "until", "expires_at": "2026-11-24 18:30"}
    )
    assert result["status"] == "recorded"
    assert result["expires_at"] == "2026-11-24T18:30"
    assert result["write_issue"] == "CannotConnect"
    hub.write_guest_schedule.assert_awaited_once()


@pytest.mark.asyncio
async def test_acknowledged_write_without_recorded_timeout_is_unverified(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    hub = fixture_hub()
    hub.read_wifi.side_effect = [TIMER, WIFI] * 4
    reply = await apply_owned_session(
        hub, "guest_schedule", {"mode": "until", "expires_at": "2026-11-24 18:30"}
    )
    assert reply["status"] == "unverified" and reply["readback"]["expires_at"] is None
    assert KEY not in repr(reply)
    hub.write_guest_schedule.assert_awaited_once()


@pytest.mark.asyncio
async def test_recorded_expiry_is_unverified_if_a_primary_key_changes(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    hub = fixture_hub()
    hub.read_wifi.side_effect = [TIMER, WIFI] + [
        TIMER | {"ActiveTimeout": "24/11/2026-18:30"},
        WIFI | {"50Passphrase": "unexpected-primary-key"},
    ] * 3
    reply = await apply_owned_session(
        hub, "guest_schedule", {"mode": "until", "expires_at": "2026-11-24 18:30"}
    )
    assert reply["status"] == "unverified"
    assert reply["readback"]["expires_at"] == "2026-11-24T18:30"
    assert "unexpected-primary-key" not in repr(reply)
    hub.write_guest_schedule.assert_awaited_once()


@pytest.mark.asyncio
async def test_read_returns_wizard_schedule_without_using_settings_page_or_returning_secret():
    hub = fixture_hub()
    hub.read_wifi.return_value = TIMER | {"ActiveTimeout": "24/11/2026-18:30"}
    reply = await apply_owned_session(hub, "guest_schedule_read", {})
    assert reply["status"] == "read"
    assert reply["expires_at"] == "2026-11-24T18:30"
    assert KEY not in repr(reply)
    hub.read_wifi.assert_awaited_once_with("guest_expiry")
    hub.write_guest_schedule.assert_not_awaited()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("2026-03-29 01:30", "skipped or repeated"),
        ("2026-10-25 01:30", "skipped or repeated"),
        ("2026-08-15 18:05", "whole or half hour"),
        ("2025-08-15 18:00", "future"),
    ],
)
def test_bad_wall_clock_times_are_not_sent(text, message):
    with pytest.raises(ValueError, match=message):
        _requested_expiry(text, "Europe/London")
