"""Synthetic checks for explicit setters and readback; no live Hub traffic."""

from asyncio import Event
from contextlib import asynccontextmanager
import json
from unittest.mock import AsyncMock

import pytest

from custom_components.virgin_hub4 import controls, verification
from custom_components.virgin_hub4.client import CannotConnect, HubClient
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from test_client import FakeHttp, LOGIN, MODE, fixture_hub
from test_parser import js


@pytest.mark.asyncio
async def test_light_ring_wire_contract_and_readback():
    session = FakeHttp(
        MODE,
        LOGIN,
        js(lightring_value="0"),
        '"Updated successfully"',
        js(lightring_value="2"),
        "",
    )
    hub = HubClient(session, "192.168.0.1")
    await hub.login("fixture-pass")
    result = await apply_owned_session(hub, "light_ring", {"mode": "manual", "brightness": 2})
    assert await hub.logout()
    assert result == {"status": "verified", "group": "light_ring", "readback": {"value": 2}}
    path, options = session.requests[3]
    assert path == "/php/ajaxSet_lightring_data.php"
    assert options["data"] == {"lightRing": '{"lightRing":2}', "opType": "WRITE"}


@pytest.mark.asyncio
async def test_mtu_invalid_and_no_op_dont_send_writes():
    hub = fixture_hub()
    hub.read_script.return_value = js(MTUSize="1500")
    assert (await apply_owned_session(hub, "mtu", {"value": 1500}))["status"] == "unchanged"
    with pytest.raises(InvalidSetting, match="1280 and 1500"):
        await apply_owned_session(hub, "mtu", {"value": 9000})
    hub.write_mtu.assert_not_awaited()


@pytest.mark.asyncio
async def test_firewall_preserves_all_other_flags_from_readback():
    home = dict(
        v4Enable="Low",
        v6Enable="Default",
        v4FragPkts="false",
        v6FragPkts="false",
        v4PortScan="true",
        v6PortScan="true",
        v4IpFlood="true",
        v6IpFlood="true",
    )
    hub = fixture_hub()
    hub.read_ip_provisioning.return_value = frozenset({"v4", "v6"})
    hub.read_script.side_effect = [js(**home), js(**(home | {"v4FragPkts": "true"}))]
    result = await apply_owned_session(hub, "firewall", {"v4_block_fragments": True})
    assert result["status"] == "verified"
    hub.write_firewall.assert_awaited_once_with(
        {
            "v4Enable": True,
            "v6Enable": True,
            "v4FragPkts": True,
            "v6FragPkts": False,
            "v4PortScan": True,
            "v6PortScan": True,
            "v4IpFlood": True,
            "v6IpFlood": True,
        }
    )


@pytest.mark.asyncio
async def test_a_lost_write_response_uses_readback_not_a_replay():
    hub = fixture_hub()
    hub.read_script.side_effect = [js(UPnP_Status="false"), js(UPnP_Status="true")]
    hub.write_upnp.side_effect = CannotConnect("response interrupted")
    result = await apply_owned_session(hub, "upnp", {"enabled": True})
    assert result["status"] == "verified"
    hub.write_upnp.assert_awaited_once_with(True)


@pytest.mark.asyncio
async def test_upnp_uses_the_status_route_but_an_explicit_setter_body():
    session = FakeHttp(MODE, LOGIN, js(UPnP_Status="true"), "")
    hub = HubClient(session, "192.168.0.1")
    await hub.login("fixture-pass")
    await hub.write_upnp(True)
    assert await hub.logout()
    path, request = session.requests[2]
    assert path == "/php/upnp_setting_data.php"
    assert json.loads(request["data"]["UPnPData"]) == {"UPnP_Status": 1}


@pytest.mark.asyncio
async def test_ack_without_changed_readback_is_unverified(monkeypatch):
    monkeypatch.setattr(verification, "READBACK_SECONDS", 0)
    hub = fixture_hub()
    hub.read_script.return_value = js(UPnP_Status="false")
    outcome = await apply_owned_session(hub, "upnp", {"enabled": True})
    assert outcome["status"] == "unverified"
    hub.write_upnp.assert_awaited_once()


@pytest.mark.asyncio
async def test_dmz_validates_against_hub_lan():
    hub = fixture_hub()
    before = dict(
        DMZ_State="false", DMZ_Ip="0.0.0.0", LAN_Ip="192.168.0.1", StartLanMask="255.255.255.0"
    )
    hub.read_script.return_value = js(**before)
    for target in ("10.1.2.3", "192.168.0.1", "192.168.0.255"):
        with pytest.raises(InvalidSetting):
            await apply_owned_session(hub, "dmz", {"enabled": True, "target": target})
    hub.write_dmz.assert_not_awaited()
    hub.read_script.side_effect = [
        js(**before),
        js(
            **(
                before
                | {
                    "DMZ_State": "true",
                    "DMZ_Ip": "192.168.0.41",
                }
            )
        ),
    ]
    result = await apply_owned_session(hub, "dmz", {"enabled": True, "target": "192.168.0.41"})
    assert result["status"] == "verified"
    hub.write_dmz.assert_awaited_once_with(True, "192.168.0.41")


@pytest.mark.asyncio
async def test_a_stalled_guest_read_is_bounded_and_releases_its_session(monkeypatch):
    hub = fixture_hub()
    before = {
        "enable": "0",
        "ssid": "Fixture Guest",
        "broadcast": "1",
        "security": "4",
        "passphrase": "synthetic-guest-key",
    }

    async def stalled_read(_):
        if hub.read_wifi.await_count == 1:
            return before
        await Event().wait()

    hub.read_wifi.side_effect = stalled_read
    closed = []

    @asynccontextmanager
    async def session(*_):
        try:
            yield hub
        finally:
            closed.append(hub)

    monkeypatch.setattr(controls, "owned_session", session)
    monkeypatch.setattr(controls, "_GUEST_POLL_SECONDS", 0.005)
    monkeypatch.setattr(controls, "_GUEST_READBACK_SECONDS", 0.1)
    monkeypatch.setattr(controls, "_GUEST_FINAL_READ_SECONDS", 0.02)
    result = await controls.apply_setting("192.168.0.1", "fixture-pass", "guest", {"ssid": "New"})
    assert result["status"] == "outcome_unknown"
    assert result["verification_issue"] == "verification_timeout"
    assert result["readback"] is None
    assert closed == [hub]
    assert hub.read_wifi.await_count == 3  # Baseline, stalled regular poll, bounded final poll.
    hub.write_guest.assert_awaited_once()


@pytest.mark.asyncio
async def test_wps_switch_polls_after_a_lost_write_reply(monkeypatch):
    monkeypatch.setattr(verification, "sleep", AsyncMock())
    hub = fixture_hub()
    on, off = js(WPSPbcEnable="true"), js(WPSPbcEnable="false")
    hub.read_script.side_effect = [on, on, CannotConnect("busy"), on, off, off, on]
    hub.write_wps.side_effect = [CannotConnect("write reply lost"), None]

    disabled = await apply_owned_session(hub, "wps", {"enabled": False})
    assert disabled["status"] == "verified" and disabled["readback"] == {"enabled": False}
    assert disabled["write_issue"] == "CannotConnect"
    assert hub.read_script.await_count == 5
    hub.write_wps.assert_awaited_once_with(False)

    restored = await apply_owned_session(hub, "wps", {"enabled": True})
    assert restored["status"] == "verified" and restored["readback"] == {"enabled": True}
    assert [call.args for call in hub.write_wps.await_args_list] == [(False,), (True,)]


@pytest.mark.asyncio
async def test_wps_requires_fresh_result_from_the_same_band(monkeypatch):
    monkeypatch.setattr(verification, "sleep", AsyncMock())
    hub = fixture_hub()
    hub.read_script.return_value = js(WPSPbcEnable="true")
    hub.read_wps_result.side_effect = [
        {"WPSstatus": "Success", "WPS50status": "Idle"},
        {"WPSstatus": "Success", "WPS50status": "Running"},
        {"WPSstatus": "Success", "WPS50status": "Success"},
    ]
    result = await apply_owned_session(hub, "wps_registration", {})
    assert result["status"] == "success"
    assert result["readback"]["WPS50status"] == "Success"
    assert hub.read_wps_result.await_count == 3
    hub.start_wps.assert_awaited_once()
    hub.clear_failed_wps.assert_not_awaited()


@pytest.mark.parametrize("lost_reply", [False, True])
async def test_fresh_failed_wps_is_cleared_once(monkeypatch, lost_reply):
    monkeypatch.setattr(verification, "sleep", AsyncMock())
    hub = fixture_hub()
    hub.read_script.return_value = js(WPSPbcEnable="true")
    idle = {"WPSstatus": "Idle", "WPS50status": "Idle"}
    failed = {band: "Failed" for band in idle}
    hub.read_wps_result.side_effect = [
        failed,  # Old failure is not enough.
        failed,
        {band: "In progress" for band in idle},
        failed,
    ]
    if lost_reply:
        hub.clear_failed_wps.side_effect = CannotConnect("cleanup reply lost")

    result = await apply_owned_session(hub, "wps_registration", {})

    assert result["status"] == "failed" and result["readback"] == failed
    assert result["cleanup"] == ("unverified" if lost_reply else "acknowledged")
    assert result.get("cleanup_issue") == ("CannotConnect" if lost_reply else None)
    assert hub.read_wps_result.await_count == 4
    hub.start_wps.assert_awaited_once()
    hub.clear_failed_wps.assert_awaited_once()
    hub.write_wps.assert_not_awaited()


async def test_wps_success_takes_priority_over_failure_in_same_read(monkeypatch):
    monkeypatch.setattr(verification, "sleep", AsyncMock())
    hub = fixture_hub()
    hub.read_script.return_value = js(WPSPbcEnable="true")
    hub.read_wps_result.side_effect = [
        {"WPSstatus": "Idle", "WPS50status": "Idle"},
        {"WPSstatus": "Failed", "WPS50status": "Success"},
    ]
    result = await apply_owned_session(hub, "wps_registration", {})
    assert result["status"] == "success"
    hub.clear_failed_wps.assert_not_awaited()


async def test_unconfirmed_wps_does_not_clear_an_old_failure(monkeypatch):
    monkeypatch.setattr(verification, "READBACK_SECONDS", 0)
    hub = fixture_hub()
    hub.read_script.return_value = js(WPSPbcEnable="true")
    hub.read_wps_result.return_value = {"WPSstatus": "Failed", "WPS50status": "Failed"}
    result = await apply_owned_session(hub, "wps_registration", {})
    assert result["status"] == "timeout"
    hub.start_wps.assert_awaited_once()
    hub.clear_failed_wps.assert_not_awaited()


async def test_dmz_does_not_offer_clearing_to_an_unset_target():
    hub = fixture_hub()
    network = {"LAN_Ip": "192.168.0.1", "StartLanMask": "255.255.255.0"}
    before = js(DMZ_State="true", DMZ_Ip="192.168.0.9", **network)
    hub.read_script.return_value = before
    with pytest.raises(InvalidSetting, match="usable host"):
        await apply_owned_session(hub, "dmz", {"enabled": False, "target": "0.0.0.0"})
    hub.write_dmz.assert_not_awaited()


async def test_wps_clear_sends_the_portals_two_band_cleanup_only():
    http = FakeHttp(MODE, LOGIN, '"OK"', "")
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    await hub.clear_failed_wps()
    assert await hub.logout()
    path, request = http.requests[2]
    assert path == "/php/ajaxSet_wifi_wps.php"
    assert request["data"] == {"WPSdata": '{"WpsPushButton":"3","Wps50PushButton":"3"}'}
