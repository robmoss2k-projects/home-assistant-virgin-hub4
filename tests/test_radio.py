"""Offline radio form and region/channel validation tests."""

from unittest.mock import AsyncMock

import pytest

from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from custom_components.virgin_hub4.client import CannotConnect, InvalidResponse
from custom_components.virgin_hub4.radio import read_radio
from test_parser import js


BASE = {
    "24g_stat": "Up",
    "24g_channel_mode": "true",
    "24g_channel": "1",
    "24g_std": "g,n",
    "24g_chbw": "20MHz",
    "24g_channelList": "1,6,11",
    "5g_stat": "Up",
    "5g_channel_mode": "true",
    "5g_channel": "108",
    "5g_std": "a,n,ac",
    "5g_chbw": "80MHz",
    "5g_channelList": "36,108,140",
}
SMART_OFF = {
    "sonAdminStatus": "true",
    "sonOperationalStatus": "false",
    "HideSmartWifiSection": "false",
}
SMART_ON = SMART_OFF | {"sonOperationalStatus": "true"}


async def test_radio_edit_preserves_other_band_and_verifies_manual_channel():
    hub = AsyncMock()
    hub.read_script.side_effect = [
        js(**BASE),
        js(**(BASE | {"24g_channel_mode": "false", "24g_channel": "6"})),
    ]
    hub.read_wifi.return_value = SMART_OFF
    outcome = await apply_owned_session(hub, "radio", {"24g_automatic": False, "24g_channel": 6})
    assert outcome["status"] == "verified"
    hub.write_radio.assert_awaited_once_with(
        {
            "js_24g_stat": "true",
            "js_24g_channel_mode": "false",
            "js_24g_channel": 6,
            "js_24g_mode": "g,n",
            "js_24g_channelBW": "20MHz",
            "js_5g_stat": "true",
            "js_5g_channel_mode": "true",
            "js_5g_channel": 108,
            "js_5g_mode": "a,n,ac",
            "js_5g_channelBW": "80MHz",
        }
    )


async def test_radio_checks_region_bandwidth_and_smart_wifi_before_writing():
    hub = AsyncMock()
    hub.read_script.return_value = js(**BASE)
    hub.read_wifi.return_value = SMART_ON
    with pytest.raises(InvalidSetting, match="Disable Smart Wi-Fi"):
        await apply_owned_session(hub, "radio", {"24g_automatic": False, "24g_channel": 6})
    hub.read_wifi.return_value = SMART_OFF
    with pytest.raises(InvalidSetting, match="channel as available"):
        await apply_owned_session(hub, "radio", {"24g_automatic": False, "24g_channel": 14})
    with pytest.raises(InvalidSetting, match="20 MHz"):
        await apply_owned_session(
            hub, "radio", {"5g_automatic": False, "5g_channel": 140, "confirm_dfs": True}
        )
    hub.write_radio.assert_not_awaited()


@pytest.mark.parametrize("requested", [{"24g_enabled": False}, {"5g_standard": "n"}])
async def test_smart_wifi_active_locks_radio_enable_and_standard(requested):
    hub = AsyncMock()
    hub.read_script.return_value = js(**BASE)
    hub.read_wifi.return_value = SMART_ON
    with pytest.raises(InvalidSetting, match="Disable Smart Wi-Fi"):
        await apply_owned_session(hub, "radio", requested)
    hub.write_radio.assert_not_awaited()


@pytest.mark.parametrize(
    "override", [{"HideSmartWifiSection": "true"}, {"sonAdminStatus": "false"}]
)
async def test_hidden_or_provider_disabled_smart_wifi_is_not_written(override):
    hub = AsyncMock()
    hub.read_script.return_value = js(**BASE)
    hub.read_wifi.return_value = SMART_OFF | override
    assert (await apply_owned_session(hub, "radio", {"optimisation": False}))[
        "status"
    ] == "unchanged"
    with pytest.raises(InvalidSetting, match="does not expose an editable"):
        await apply_owned_session(hub, "radio", {"optimisation": True})
    hub.write_radio.assert_not_awaited()


async def test_disabled_radio_rejects_channel_changes_and_optimisation_requires_a_radio():
    hub = AsyncMock()
    hub.read_script.return_value = js(**(BASE | {"24g_stat": "Down", "5g_stat": "Down"}))
    hub.read_wifi.return_value = SMART_OFF
    with pytest.raises(InvalidSetting, match="Enable at least one radio"):
        await apply_owned_session(hub, "radio", {"optimisation": True})
    with pytest.raises(InvalidSetting, match="Enable the 24g radio"):
        await apply_owned_session(hub, "radio", {"24g_automatic": False, "24g_channel": 6})
    hub.write_radio.assert_not_awaited()


async def test_can_disable_optimisation_and_change_an_enabled_radio_in_one_write():
    hub = AsyncMock()
    hub.read_script.side_effect = [js(**BASE), js(**(BASE | {"5g_std": "ac"}))]
    hub.read_wifi.side_effect = [SMART_ON, SMART_OFF]
    outcome = await apply_owned_session(hub, "radio", {"optimisation": False, "5g_standard": "ac"})
    assert outcome["status"] == "verified"
    hub.write_radio.assert_awaited_once()
    payload = hub.write_radio.await_args.args[0]
    assert payload["sonOperationalStatus"] == "false"
    assert payload["js_5g_mode"] == "ac"


async def test_hidden_smart_wifi_does_not_lock_the_visible_radio_buttons():
    hub = AsyncMock()
    hub.read_script.side_effect = [js(**BASE), js(**(BASE | {"5g_stat": "Down"}))]
    hub.read_wifi.return_value = SMART_ON | {"HideSmartWifiSection": "true"}
    outcome = await apply_owned_session(hub, "radio", {"5g_enabled": False})
    assert outcome["status"] == "verified"
    assert "sonOperationalStatus" not in hub.write_radio.await_args.args[0]


@pytest.mark.parametrize("band", ["24g", "5g"])
async def test_lower_layer_down_can_verify_disable_and_is_a_valid_restore_baseline(band):
    hub = AsyncMock()
    off = js(**(BASE | {f"{band}_stat": "LowerLayerDown"}))
    on = js(**BASE)
    hub.read_script.side_effect = [on, off, off, on]
    hub.read_wifi.return_value = SMART_OFF
    hub.write_radio.side_effect = [CannotConnect("write reply lost"), None]

    result = await apply_owned_session(hub, "radio", {f"{band}_enabled": False})
    assert result["status"] == "verified"
    assert result["readback"][f"{band}_enabled"] is False
    assert result["write_issue"] == "CannotConnect"
    hub.write_radio.assert_awaited_once()

    result = await apply_owned_session(hub, "radio", {f"{band}_enabled": True})
    assert result["status"] == "verified"
    assert result["readback"][f"{band}_enabled"] is True
    assert [call.args[0][f"js_{band}_stat"] for call in hub.write_radio.await_args_list] == [
        "false",
        "true",
    ]


def test_unrecognised_radio_status_is_still_rejected():
    with pytest.raises(InvalidResponse, match="24g settings"):
        read_radio(BASE | {"24g_stat": "Unknown"}, SMART_OFF)


async def test_portal_twenty_forty_choice_sends_the_forty_token():
    hub = AsyncMock()
    hub.read_wifi.return_value = SMART_OFF
    hub.read_script.return_value = js(**BASE)
    with pytest.raises(InvalidSetting, match="does not offer that 24g channel width"):
        await apply_owned_session(hub, "radio", {"24g_width": "20,40MHz"})
    hub.write_radio.assert_not_awaited()
    hub.read_script.side_effect = [js(**BASE), js(**(BASE | {"24g_chbw": "40MHz"}))]
    result = await apply_owned_session(hub, "radio", {"24g_width": "40MHz"})
    assert result["status"] == "verified"
    assert hub.write_radio.await_args.args[0]["js_24g_channelBW"] == "40MHz"
