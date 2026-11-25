"""Offline DHCP configuration and protection of connected clients."""

import json
from unittest.mock import AsyncMock

import pytest

from custom_components.virgin_hub4.client import CannotConnect, HubClient
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from test_client import FakeHttp, LOGIN, MODE
from test_parser import js

SETTINGS = {
    "getting": "dhcpInfo",
    "enableV4": 1,
    "startAddrV4": "192.168.0.10",
    "endAddrV4": "192.168.0.109",
    "subnetIp": "192.168.0.1",
    "subnetMask": "255.255.255.0",
    "leaseTimeV4": "86400",
    "typeV6": 2,
}
GATEWAY_MAC = "02:00:00:00:00:01"
DISPOSABLE_MAC = "02:00:00:00:00:02"
CLIENT = ["Test gateway", GATEWAY_MAC, "192.168.0.10", "600", "Ethernet", ""]
DUAL_STACK = '{"deviceMode":"3","dsliteMode":"0"}'


def fragment(*, editable=False, **data):
    settings = SETTINGS | data
    return js(
        lan_gateway_ip=settings["subnetIp"],
        lan_subnet_mask=settings["subnetMask"],
        lan_start_dhcp=settings["startAddrV4"],
        lan_end_dhcp=settings["endAddrV4"],
        hide_customer_dhcp_lan_change=not editable,
    )


def clients(*reservations):
    return {"getting": "clientTbl", "staticData": list(reservations), "clientData": [CLIENT]}


async def apply(hub, group, **fields):
    if isinstance(hub, AsyncMock) and not isinstance(
        hub.read_ip_provisioning.return_value, frozenset
    ):
        hub.read_ip_provisioning.return_value = frozenset({"v4", "v6"})
    return await apply_owned_session(hub, group, fields)


@pytest.mark.asyncio
async def test_ipv4_lease_time_preserves_lan_and_pool():
    http = FakeHttp(
        MODE,
        LOGIN,
        DUAL_STACK,
        fragment(),
        json.dumps(SETTINGS),
        json.dumps(clients()),
        '"OK"',
        fragment(),
        json.dumps(SETTINGS | {"leaseTimeV4": "43200"}),
        json.dumps(clients()),
        "",
    )
    hub = HubClient(http, "192.168.0.1")
    await hub.login("session-fixture")
    result = await apply(hub, "dhcp_v4", lease_seconds=43200)
    assert result["status"] == "verified"
    assert await hub.logout()
    path, options = http.requests[6]
    assert path == "/php/ajaxSet_dhcp_setting_data.php"
    assert json.loads(options["data"]["DhcpData"]) == {
        "setting": "dhcpV4",
        "enableV4": "true",
        "startAddrV4": "192.168.0.10",
        "endAddrV4": "192.168.0.109",
        "subnetMask": "255.255.255.0",
        "leaseTimeV4": "43200",
        "lanGwAddrV4": "192.168.0.1",
    }


@pytest.mark.asyncio
async def test_ipv6_writes_only_mode():
    hub = AsyncMock()
    hub.read_script.return_value = fragment()
    hub.read_dhcp.side_effect = [SETTINGS, SETTINGS | {"typeV6": 1}]
    hub.write_dhcp.return_value = None
    assert (await apply(hub, "dhcp_v6", mode="stateful"))["status"] == "verified"
    hub.write_dhcp.assert_awaited_once_with({"setting": "dhcpV6", "typeV6": "Stateful"})


@pytest.mark.asyncio
async def test_pool_cannot_displace_client_without_confirming_and_hidden_subnet_is_rejected():
    hub = AsyncMock()
    hub.read_script.return_value = fragment()
    hub.read_dhcp.side_effect = [SETTINGS, clients()] * 3
    with pytest.raises(InvalidSetting, match="network-change confirmation"):
        await apply(hub, "dhcp_v4", pool_start="192.168.0.11")
    with pytest.raises(InvalidSetting, match="hides the LAN subnet mask"):
        await apply(hub, "dhcp_v4", subnet_mask="255.255.0.0", confirm_network_change=True)
    with pytest.raises(InvalidSetting, match="network-change confirmation"):
        await apply(hub, "dhcp_v4", enabled=False)
    hub.write_dhcp.assert_not_awaited()


@pytest.mark.asyncio
async def test_readdress_connection_loss_is_not_success_and_includes_expected_hub_address(
    monkeypatch,
):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    hub = AsyncMock()
    hub.read_script.side_effect = [
        fragment(editable=True),
        *([CannotConnect("address changed")] * 3),
    ]
    hub.read_dhcp.side_effect = [SETTINGS, clients()]
    hub.write_dhcp.side_effect = CannotConnect("reply lost")
    result = await apply(hub, "dhcp_v4", pool_start="192.168.1.10", confirm_network_change=True)
    assert result == {
        "status": "unverified",
        "reason": "CannotConnect",
        "readback": None,
        "requested_gateway": "192.168.1.1",
    }
    assert hub.write_dhcp.await_args.args[0]["endAddrV4"] == "192.168.1.109"
    hub.write_dhcp.assert_awaited_once()


@pytest.mark.asyncio
async def test_reserve_outside_pool_then_match_mac_and_address_to_delete():
    hub = AsyncMock()
    hub.read_script.return_value = fragment()
    neighbour = [GATEWAY_MAC, "192.168.0.10"]
    disposable = [DISPOSABLE_MAC, "192.168.0.150"]
    hub.read_dhcp.side_effect = [
        SETTINGS,
        clients(neighbour),
        SETTINGS,
        clients(neighbour, disposable),
        SETTINGS,
        clients(neighbour, disposable),
        SETTINGS,
        clients(neighbour),
    ]
    hub.write_dhcp.return_value = None
    fields = {"mac": DISPOSABLE_MAC, "address": "192.168.0.150"}
    assert (await apply(hub, "dhcp_reservations", operation="add", **fields))[
        "status"
    ] == "verified"
    assert hub.write_dhcp.await_args.args[0] == {
        "setting": "static",
        "staticMAC": DISPOSABLE_MAC,
        "staticIP": "192.168.0.150",
    }
    result = await apply(hub, "dhcp_reservations", operation="delete", **fields)
    assert result["status"] == "verified"
    assert result["reservations"] == [{"mac": GATEWAY_MAC, "address": "192.168.0.10"}]
    assert hub.write_dhcp.await_args.args[0] == {"setting": "delete", "delIdx": ["192.168.0.150"]}


@pytest.mark.asyncio
async def test_no_reservation_for_another_devices_lease():
    hub = AsyncMock()
    hub.read_script.return_value = fragment()
    hub.read_dhcp.side_effect = [SETTINGS, clients()]
    with pytest.raises(InvalidSetting, match="different connected device"):
        await apply(
            hub, "dhcp_reservations", operation="add", mac=DISPOSABLE_MAC, address="192.168.0.10"
        )
    hub.write_dhcp.assert_not_awaited()


@pytest.mark.asyncio
async def test_report_hub_rejection_without_replaying_or_exposing_reply(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    read = (fragment(), json.dumps(SETTINGS), json.dumps(clients()))
    http = FakeHttp(MODE, LOGIN, DUAL_STACK, *read, " LanIPError ", "")
    hub = HubClient(http, "192.168.0.1")
    await hub.login("session-fixture")
    result = await apply(hub, "dhcp_v4", pool_end="192.168.0.110")
    assert result["status"] == "rejected"
    assert result["reason"] == "The Hub rejected the start address: it is in use elsewhere."
    assert await hub.logout()
    assert [path for path, _ in http.requests].count("/php/ajaxSet_dhcp_setting_data.php") == 1
