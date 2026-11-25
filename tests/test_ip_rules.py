"""Synthetic portal rule tables and authenticated wire-contract tests."""

import json

import pytest

from custom_components.virgin_hub4.client import HubClient, InvalidResponse
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from test_client import DUAL_STACK, FakeHttp, LOGIN, MODE, fixture_hub
from test_parser import js

PORTS = dict(SrcPortStart="1000", SrcPortEnd="1001", DstPortStart="443", DstPortEnd="443")
V4 = dict(
    SrcStartAddr="192.0.2.11",
    SrcEndAddr="192.0.2.12",
    DstStartAddr="0.0.0.0",
    DstEndAddr="0.0.0.0",
    Protocol="BOTH",
    **PORTS,
)
V6 = dict(
    SrcStartAddr="2001:db8::",
    PrefixSrc="64",
    DstStartAddr="2001:db8:1::55",
    PrefixDst="0",
    Protocol="ICMPv6",
    IPv6Direction="outgoing",
    Action="Deny",
    **dict.fromkeys(PORTS, "0"),
)


def table(v4=(), v6=(), *, gateway="192.168.0.1"):
    def export(rows):
        columns = {}
        for index, row in enumerate(rows, 1):
            for field, value in row.items():
                columns.setdefault(field, {})[str(index)] = value
        return json.dumps(columns)

    return js(
        ip_v4_filter_data=export(v4),
        service_v4_number_of_entries=str(len(v4)),
        ip_v6_filter_data=export(v6),
        service_v6_number_of_entries=str(len(v6)),
        lan_gateway_ip=gateway,
        lan_start_dhcp="192.0.2.2",
        lan_end_dhcp="192.0.2.254",
    )


def row(payload, key="14", enabled="true"):
    return payload | {"KeyVal": key, "EnableVal": enabled}


async def apply(hub, family, operation, **kwargs):
    return await apply_owned_session(
        hub, "ip_rules", {"family": family, "operation": operation, **kwargs}
    )


@pytest.mark.parametrize("ip6", (False, True))
@pytest.mark.asyncio
async def test_create_uses_exact_family_wire_payload(ip6):
    family = "ipv6" if ip6 else "ipv4"
    fw = V6 if ip6 else V4
    after = table(v6=[row(fw)]) if ip6 else table(v4=[row(fw)])
    device = [js(swVersion="other-firmware", systemUptime="1 days 00h:00m:00s")] if ip6 else []
    http = FakeHttp(MODE, LOGIN, DUAL_STACK, table(), *device, "OK", after, "")
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    if ip6:
        fields = dict(
            protocol="ICMPv6",
            source="2001:db8::/64",
            destination="2001:db8:1::55",
            direction="outgoing",
            policy="Deny",
        )
    else:
        fields = dict(
            protocol="BOTH",
            source="192.0.2.11-192.0.2.12",
            destination="any",
            source_port_start=1000,
            source_port_end=1001,
            destination_port_start=443,
            destination_port_end=443,
        )
    result = await apply(hub, family, "add", **fields, enabled=True)
    assert result["status"] == "verified"
    assert result["rules"][0]["source"] == fields["source"]
    assert "_key" not in result["rules"][0]
    assert await hub.logout()
    version = 6 if ip6 else 4
    path, options = http.requests[4 + len(device)]
    assert path == f"/php/ajaxSet_ipv{version}_filter_data.php"
    assert json.loads(options["data"][f"IPFilter_V{version}_Data"]) == fw | {"Enable": 1}


async def test_known_firmware_rejects_non_host_ipv6_prefix_without_writing():
    hub = fixture_hub(spec=HubClient)
    hub.read_script.side_effect = [
        table(),
        js(swVersion="01.04.092.07.23.EURO.PC20", systemUptime="1 days 00h:00m:00s"),
    ]
    with pytest.raises(InvalidSetting, match="drops IPv6 prefixes"):
        await apply(
            hub,
            "ipv6",
            "add",
            protocol="ICMPv6",
            enabled=False,
            source="2001:db8::/64",
            destination="any",
            direction="incoming",
            policy="Deny",
        )
    hub.add_ip_rule.assert_not_awaited()


@pytest.mark.asyncio
async def test_disabling_uses_current_key_and_keeps_neighbours():
    twin = row(V6 | {"Action": "Allow", "IPv6Direction": "incoming"}, key="21")
    old = table(v4=[row(V4)], v6=[row(V6), twin])
    new = table(v4=[row(V4)], v6=[twin, row(V6, key=18)])
    after = table(v4=[row(V4)], v6=[twin, row(V6, key=18, enabled="false")])
    http = FakeHttp(MODE, LOGIN, old, DUAL_STACK, new, "OK", after, "")
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    rules = (await apply(hub, "ipv6", "list"))["rules"]
    result = await apply(hub, "ipv6", "set_enabled", rule_id=rules[0]["id"], enabled=False)
    assert result["status"] == "verified"
    assert [rule["enabled"] for rule in result["rules"]] == [True, False]
    assert await hub.logout()
    path, options = http.requests[5]
    assert path == "/php/ajaxSet_ipfilter_data.php"
    assert json.loads(options["data"]["ipFilterDelOrEnable"]) == {
        "Key": 18,
        "Enable": "false",
        "Delete": "false",
        "IPV6": "true",
    }


@pytest.mark.asyncio
async def test_delete_reports_other_family_change_and_never_replays(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    hub = fixture_hub()
    before = table(v4=[row(V4)], v6=[row(V6)])
    hub.read_script.side_effect = [before, before, table(), table(), table()]
    rules = (await apply(hub, "ipv4", "list"))["rules"]
    result = await apply(hub, "ipv4", "delete", rule_id=rules[0]["id"])
    assert result["status"] == "unverified"
    assert result["rules"] == []
    hub.edit_ip_rule.assert_awaited_once_with("14", ip6=False, enabled=False, delete=True)


@pytest.mark.asyncio
async def test_no_write_on_invalid_address_or_incomplete_table():
    hub = fixture_hub()
    hub.read_script.return_value = table()
    with pytest.raises(InvalidSetting, match="own LAN address"):
        await apply(
            hub,
            "ipv4",
            "add",
            protocol="All",
            source="192.168.0.1",
            destination="any",
            enabled=True,
        )
    with pytest.raises(InvalidSetting, match="/64 to /127"):
        await apply(
            hub,
            "ipv6",
            "add",
            protocol="All",
            source="2001:db8::/56",
            destination="any",
            enabled=False,
            policy="Allow",
            direction="incoming",
        )
    hub.read_script.return_value = table(v4=[row(V4) | {"KeyVal": ""}])
    with pytest.raises(InvalidResponse, match="usable key"):
        await apply(hub, "ipv4", "delete", rule_id="arbitrary")
    hub.edit_ip_rule.assert_not_awaited()
    hub.add_ip_rule.assert_not_awaited()
