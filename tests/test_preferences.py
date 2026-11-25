"""Offline tests for the preferences the Hub actually accepts."""

import json
from unittest.mock import AsyncMock

import pytest

from custom_components.virgin_hub4.client import CannotConnect, HubClient
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from custom_components.virgin_hub4.preferences import decode_languages
from test_client import FakeHttp, LOGIN, MODE

TARGET = "02:00:00:00:00:01"
OTHER = "02:00:00:00:00:02"


def _devices(target_label, other_label="Neighbour"):
    return {
        "numHostEnt": 2,
        "phyAddress": [TARGET, OTHER],
        "hostName": ["upstream-hostname", "another-hostname"],
        "FriendlyName": [target_label, other_label],
    }


@pytest.mark.asyncio
async def test_device_name_clears_using_the_portal_write_and_verifies_readback():
    http = FakeHttp(MODE, LOGIN, json.dumps(_devices("Old")), "OK", json.dumps(_devices("")), "")
    client = HubClient(http, "192.168.0.1")
    await client.login("fixture-pass")
    result = await apply_owned_session(client, "device_label", {"mac": TARGET, "label": ""})
    assert result == {"status": "verified", "label": "", "mac": TARGET}
    assert await client.logout()
    path, options = http.requests[3]
    assert path == "/php/associated_devices_data.php"
    assert options["data"]["opType"] == "WRITE"
    assert json.loads(options["data"]["assocDevData"]) == {"FriendlyName": "", "MACAddress": TARGET}


@pytest.mark.asyncio
async def test_name_unchanged_invalid_and_unknown_device_do_not_write():
    hub = AsyncMock()
    hub.read_clients.return_value = _devices("Current")
    assert (await apply_owned_session(hub, "device_label", {"mac": TARGET, "label": "Current"}))[
        "status"
    ] == "unchanged"
    with pytest.raises(InvalidSetting, match="among associated devices"):
        await apply_owned_session(
            hub, "device_label", {"mac": "02:00:00:00:00:03", "label": "Other"}
        )
    with pytest.raises(InvalidSetting, match="no HTML"):
        await apply_owned_session(hub, "device_label", {"mac": TARGET, "label": "<new>"})
    hub.write_device_label.assert_not_awaited()


@pytest.mark.asyncio
async def test_label_write_is_unverified_if_neighbour_changed(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    hub = AsyncMock()
    hub.read_clients.side_effect = [_devices("Old"), *([_devices("New", "Changed")] * 3)]
    result = await apply_owned_session(hub, "device_label", {"mac": TARGET, "label": "New"})
    assert result["status"] == "unverified"
    hub.write_device_label.assert_awaited_once_with(TARGET, "New")


@pytest.mark.asyncio
async def test_language_single_field_write_and_readback():
    available = json.dumps({"availableLang": "en,tk,fr,de,nl,ro,it,pl,cz,hu,es,sk"})
    http = FakeHttp(MODE, LOGIN, '{"lang":"en"}', available, "{}", '{"lang":"fr"}', available, "")
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    result = await apply_owned_session(hub, "portal_language", {"language": "fr"})
    assert result["status"] == "verified"
    assert result["language"] == "fr" and "sk" in result["available_languages"]
    assert await hub.logout()
    path, request = http.requests[4]
    assert path == "/php/user_data.php"
    assert request["data"] == {"userData": '{"lang":"fr"}', "opType": "WRITE"}


@pytest.mark.asyncio
async def test_offered_language_only_and_lost_ack_resolved_by_readback():
    hub = AsyncMock()
    hub.read_portal_language.side_effect = [
        {"lang": "en"},
        {"availableLang": "en,fr"},
        {"lang": "en"},
        {"availableLang": "en,fr"},
        {"lang": "fr"},
        {"availableLang": "en,fr"},
    ]
    with pytest.raises(InvalidSetting, match="not offered"):
        await apply_owned_session(hub, "portal_language", {"language": "ru"})
    hub.write_portal_language.assert_not_awaited()
    hub.write_portal_language.side_effect = CannotConnect("synthetic response loss")
    assert (await apply_owned_session(hub, "portal_language", {"language": " FR "}))[
        "status"
    ] == "verified"
    hub.write_portal_language.assert_awaited_once_with("fr")


def test_language_read_normalizes_and_deduplicates_available_codes():
    assert decode_languages({"lang": "en"}, {"availableLang": " en ,pt-br,en "}) == {
        "language": "en",
        "available_languages": ["en", "pt-br"],
    }
