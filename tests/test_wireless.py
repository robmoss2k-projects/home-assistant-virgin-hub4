"""The Wi-Fi write contract and preservation of credentials and neighbouring rows."""

from copy import deepcopy
import json
from unittest.mock import AsyncMock

import pytest

from custom_components.virgin_hub4.client import CannotConnect, HubClient, SessionCrypto
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from test_client import FakeHttp, LOGIN, MODE, RADIOS, encrypted_reply, fixture_hub

SETTINGS = {
    "Configuration": [
        {
            "SSID": "First &amp; second",
            "SecuritySSIDBroadcastGrp": "1",
            "SecurityModeGrp": "4",
            "Passphrase": "fixture&amp;one",
        },
        {
            "SSID": "Second",
            "SecuritySSIDBroadcastGrp": "0",
            "SecurityModeGrp": "5",
            "Passphrase": "fixture-two",
        },
    ],
    "MACFilter": [{"BssAccessModeGrp": "1"}],
}
ENTRY = {"DeviceName": "Synthetic", "MACAddress": "02:00:00:00:00:01", "SSIDIndex": 1}


def list_reply(*rows):
    return {"WirelessFilterList": list(rows)}


async def settings(hub, **changes):
    return await apply_owned_session(hub, "wifi_settings", changes)


async def access(hub, **changes):
    return await apply_owned_session(hub, "wifi_access_list", changes)


@pytest.mark.asyncio
async def test_full_form_changes_policy_and_ssid_but_keeps_keys():
    changed = deepcopy(SETTINGS)
    changed["Configuration"][0]["SSID"] = "Replacement"
    changed["MACFilter"][0]["BssAccessModeGrp"] = "3"
    http = FakeHttp(
        MODE,
        LOGIN,
        encrypted_reply(SETTINGS),
        json.dumps(list_reply(ENTRY)),
        RADIOS,
        '"OK"',
        encrypted_reply(changed),
        json.dumps(list_reply(ENTRY)),
        "",
    )
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    outcome = await settings(hub, band24_ssid="Replacement", policy="deny_list")
    assert outcome["status"] == "verified"
    assert outcome["settings"]["band50_ssid"] == "Second"
    assert not any("fixture" in repr(value) for value in outcome.values())
    assert await hub.logout()

    login = json.loads(http.requests[1][1]["data"]["configInfo"])
    path, options = http.requests[5]
    assert path == "/php/ajaxSet_wifi_settings_data.php"
    envelope = json.loads(options["data"]["wifiData"])
    assert envelope["iv"] != login["iv"]
    assert envelope["authData"] == "storeMacFilterSetting"
    assert "Configuration" not in envelope
    crypto = SessionCrypto.from_password("fixture-pass", salt=login["salt"], iv=login["iv"])
    decrypted = crypto.open_response(envelope, envelope)
    assert decrypted["Configuration"] == {
        "SSID": "Replacement",
        "SecuritySSIDBroadcastGrp": 1,
        "SecurityModeGrp": "WPA2-Personal",
        "bssIdxWPAPresharedKey": "fixture&one",
        "SSID50": "Second",
        "SecuritySSIDBroadcastGrp50": 0,
        "SecurityModeGrp50": "WPA-WPA2-Personal",
        "bssIdxWPAPresharedKey50": "fixture-two",
        "BssAccessModeGrp": 3,
    }
    assert decrypted["RemoveMacFilterDevice"] == []
    assert decrypted["WirelessFilterList"] == [ENTRY]


@pytest.mark.asyncio
async def test_add_to_second_band_only_and_delete_current_row_by_index():
    hub = fixture_hub()
    both = ENTRY | {"SSIDIndex": "2"}
    neighbour = ENTRY | {"MACAddress": "02:00:00:00:00:05", "SSIDIndex": 2}
    hub.read_wifi.return_value = SETTINGS
    hub.read_rules.side_effect = [
        list_reply(ENTRY, neighbour),
        list_reply(ENTRY, neighbour, both),
        list_reply(neighbour, both, ENTRY),
        list_reply(neighbour, both),
    ]
    target = {"mac": ENTRY["MACAddress"], "name": ENTRY["DeviceName"]}
    assert (await access(hub, operation="add", band="both", **target))["status"] == "verified"
    add = hub.write_wifi_settings.await_args
    assert add.kwargs == {"add_filter": True}
    assert add.args[0] == {
        "WirelessFilterList": [ENTRY, neighbour],
        "NewFilterDevice": [ENTRY | {"SSIDIndex": 2}],
    }
    assert (await access(hub, operation="delete", band="band24", mac=target["mac"]))[
        "status"
    ] == "verified"
    delete = hub.write_wifi_settings.await_args
    assert delete.kwargs == {"add_filter": False}
    assert delete.args[0]["RemoveMacFilterDevice"] == [2]
    assert delete.args[0]["WirelessFilterList"] == [neighbour, both, ENTRY]


@pytest.mark.asyncio
async def test_no_write_if_linking_would_copy_a_key_or_optimisation_locks_broadcast():
    hub = fixture_hub()
    hub.read_rules.return_value = list_reply()
    hub.read_wifi.side_effect = [
        SETTINGS,
        {"sonAdminStatus": "true", "sonOperationalStatus": "true"},
        SETTINGS,
        {"sonAdminStatus": "true", "sonOperationalStatus": "true"},
        SETTINGS,
        {"sonAdminStatus": "false", "sonOperationalStatus": "false"},
    ]
    with pytest.raises(InvalidSetting, match="locks broadcast"):
        await settings(hub, band24_broadcast=False)
    # Linking these two names requires aligning broadcast state as well.
    with pytest.raises(InvalidSetting, match="locks broadcast"):
        await settings(hub, band50_ssid="First & second")
    with pytest.raises(InvalidSetting, match="without changing either passphrase"):
        await settings(hub, band50_ssid="First & second")
    hub.write_wifi_settings.assert_not_awaited()


@pytest.mark.asyncio
async def test_wireless_waits_past_three_stale_reads_after_losing_the_ack(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.sleep", AsyncMock())
    hub = fixture_hub()
    changed = deepcopy(SETTINGS)
    changed["MACFilter"][0]["BssAccessModeGrp"] = "3"
    hub.read_wifi.side_effect = [SETTINGS] * 5 + [changed]
    hub.read_rules.return_value = list_reply(ENTRY)
    hub.write_wifi_settings.side_effect = CannotConnect("lost hardware reply")
    result = await settings(hub, policy="deny_list")
    assert result["status"] == "verified" and result["settings"]["policy"] == "deny_list"
    assert result["write_issue"] == "CannotConnect"
    hub.write_wifi_settings.assert_awaited_once()


@pytest.mark.asyncio
async def test_changed_readback_key_is_not_reported_as_success_or_retried(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    hub = fixture_hub()
    adjusted = deepcopy(SETTINGS)
    adjusted["Configuration"][1].update(SSID="Renamed", Passphrase="")
    hub.read_wifi.side_effect = [SETTINGS, adjusted, adjusted, adjusted]
    hub.read_rules.return_value = list_reply()
    outcome = await settings(hub, band50_ssid="Renamed")
    assert outcome["status"] == "unverified"
    assert outcome["passphrases_preserved"] is False
    assert "Passphrase" not in repr(outcome)
    hub.write_wifi_settings.assert_awaited_once()


@pytest.mark.asyncio
async def test_wireless_rule_add_sends_no_configuration_or_secrets():
    http = FakeHttp(MODE, LOGIN, '"OK"', "")
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    await hub.write_wifi_settings(
        {"NewFilterDevice": [ENTRY], "WirelessFilterList": []}, add_filter=True
    )
    assert await hub.logout()
    path, options = http.requests[2]
    assert path == "/php/ajaxSet_wifi_settings_data.php"
    assert set(json.loads(options["data"]["wifiData"])) == {
        "NewFilterDevice",
        "WirelessFilterList",
        "csrf_nonce",
    }
