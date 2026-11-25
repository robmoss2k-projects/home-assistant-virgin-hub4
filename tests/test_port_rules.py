"""Offline tests for the firmware's indexed forwarding and triggering tables."""

import pytest

from custom_components.virgin_hub4.port_rules import (
    FORWARD,
    TRIGGER,
    apply_port_rule,
    read_table,
)
from custom_components.virgin_hub4.client import InvalidResponse
from test_client import fixture_hub
from test_parser import js


def table(group, *rows):
    columns, count_key = (
        (FORWARD, "PortMappingNumberOfEntries")
        if group == "forwarding"
        else (TRIGGER, "PortTriggeringNumberOfEntries")
    )
    return {
        count_key: {"1": len(rows)},
        **{wire: {str(i): str(row[key]) for i, row in enumerate(rows, 1)} for key, wire in columns},
        "RuleSource": {
            str(i): "UPnP" if row.get("dynamic") else "Static" for i, row in enumerate(rows, 1)
        },
        "Enable": {str(i): str(row["enabled"]).lower() for i, row in enumerate(rows, 1)},
    }


FORWARD_ONE = dict(
    target="192.168.1.12",
    local_start=4001,
    local_end=4002,
    external_start=5001,
    external_end=5002,
    protocol="TCP",
    enabled=True,
)
FORWARD_TWO = FORWARD_ONE | {"target": "192.168.1.14", "external_start": 5100, "external_end": 5101}
DYNAMIC = FORWARD_ONE | {
    "dynamic": True,
    "target": "192.168.1.13",
    "external_start": 5500,
    "external_end": 5501,
}
TRIGGER_ONE = dict(
    trigger_start=6000,
    trigger_end=6001,
    forward_start=7000,
    forward_end=7001,
    protocol="UDP",
    enabled=True,
)
TRIGGER_TWO = TRIGGER_ONE | dict(
    trigger_start=6100,
    trigger_end=6101,
    forward_start=7100,
    forward_end=7101,
    enabled=False,
)


def test_firmware_empty_trigger_sentinel_is_not_a_rule():
    assert (
        read_table(
            "triggering",
            {
                "PortTriggeringNumberOfEntries": {"1": 1},
                "TriggerPortStart": {"1": ""},
            },
        )
        == []
    )


async def test_forward_create_and_overlaps():
    hub = fixture_hub()
    hub.read_script.return_value = js(
        PortMappingData={},
        StartLanIP="192.168.1.1",
        PortMappingIpSMsk="255.255.255.0",
        PortMappingIpAddrMin="192.168.1.10",
        DhcpMinAddr="192.168.1.10",
        DhcpMaxAddr="192.168.1.254",
    )
    hub.read_rules.side_effect = [table("forwarding"), table("forwarding", FORWARD_ONE)]
    result = await apply_port_rule(hub, "forwarding", FORWARD_ONE | {"operation": "add"})
    assert result["status"] == "verified"
    hub.write_port_rules.assert_awaited_once_with(
        "forwarding",
        {
            "InternalClient": "192.168.1.12",
            "InternalPort": 4001,
            "X_ARRIS_COM_InternalPortEndRange": 4002,
            "ExternalPort": 5001,
            "ExternalPortEndRange": 5002,
            "Protocol": "TCP",
            "Enable": 1,
        },
        add=True,
    )
    hub.reset_mock()
    hub.read_rules.side_effect = None
    hub.read_rules.return_value = table("forwarding", FORWARD_ONE)
    with pytest.raises(ValueError, match="overlaps"):
        await apply_port_rule(
            hub,
            "forwarding",
            FORWARD_ONE
            | {
                "operation": "add",
                "target": "192.168.1.17",
                "protocol": "BOTH",
            },
        )
    hub.write_port_rules.assert_not_awaited()


async def test_create_trigger_sends_ports_as_text_like_the_portal():
    hub = fixture_hub()
    hub.read_rules.side_effect = [table("triggering"), table("triggering", TRIGGER_TWO)]
    outcome = await apply_port_rule(hub, "triggering", TRIGGER_TWO | {"operation": "add"})
    assert outcome["status"] == "verified"
    hub.write_port_rules.assert_awaited_once_with(
        "triggering",
        {
            "TriggerStartPort": "6100",
            "TriggerEndPort": "6101",
            "TargetStartPort": "7100",
            "TargetEndPort": "7101",
            "Protocol": "UDP",
            "Enable": "false",
        },
        add=True,
    )


async def test_trigger_edit_indexes_follow_current_visible_order():
    hub = fixture_hub()
    before = table("triggering", TRIGGER_TWO, TRIGGER_ONE)
    selected = read_table("triggering", before)[0]["id"]
    hub.read_rules.side_effect = [
        before,
        table("triggering", TRIGGER_ONE, TRIGGER_TWO | {"enabled": True}),
    ]
    result = await apply_port_rule(
        hub,
        "triggering",
        {
            "operation": "set_enabled",
            "rule_id": selected,
            "enabled": True,
        },
    )
    assert result["status"] == "verified"
    hub.write_port_rules.assert_awaited_once_with(
        "triggering",
        {"Enable": [0, 1], "Delete": [-1, -1]},
        add=False,
    )


async def test_delete_must_verify_all_other_rules_were_preserved(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    hub = fixture_hub()
    before = table("triggering", TRIGGER_ONE, TRIGGER_TWO)
    selected = read_table("triggering", before)[0]["id"]
    # Target gone, but the neighbour was unintentionally enabled.
    error_snapshot = table("triggering", TRIGGER_TWO | {"enabled": True})
    hub.read_rules.side_effect = [before, error_snapshot, error_snapshot, error_snapshot]
    result = await apply_port_rule(
        hub,
        "triggering",
        {
            "operation": "delete",
            "rule_id": selected,
        },
    )
    assert result["status"] == "unverified"
    hub.write_port_rules.assert_awaited_once_with(
        "triggering",
        {"Enable": [0, -1], "Delete": [0, -1]},
        add=False,
    )


async def test_mixed_forwarding_table_uses_manual_checkbox_order_only():
    hub = fixture_hub()
    snapshot = table("forwarding", DYNAMIC, FORWARD_ONE, FORWARD_TWO)
    hub.read_rules.side_effect = [snapshot, table("forwarding", DYNAMIC, FORWARD_ONE)]
    hub.read_script.return_value = js(PortMappingData={}, UPnP_Rules="1")
    manual = read_table("forwarding", snapshot)[2]["id"]
    result = await apply_port_rule(hub, "forwarding", {"operation": "delete", "rule_id": manual})
    assert result["status"] == "verified"
    assert result["rules"][0]["dynamic"] is True
    hub.write_port_rules.assert_awaited_once_with(
        "forwarding", {"Enable": [0, 1], "Delete": [-1, 1]}, add=False
    )


async def test_mixed_forwarding_table_refuses_unrecognised_checkbox_layout():
    hub = fixture_hub()
    snapshot = table("forwarding", FORWARD_ONE, DYNAMIC)
    hub.read_rules.return_value = snapshot
    hub.read_script.return_value = js(PortMappingData={}, UPnP_Rules="0")
    manual = read_table("forwarding", snapshot)[0]["id"]
    with pytest.raises(ValueError, match="mixed-table layout"):
        await apply_port_rule(hub, "forwarding", {"operation": "delete", "rule_id": manual})
    hub.write_port_rules.assert_not_awaited()


async def test_matching_manual_change_is_unverified_if_dynamic_entries_changed(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.verification.READBACK_SECONDS", 0)
    hub = fixture_hub()
    snapshot = table("forwarding", DYNAMIC, FORWARD_ONE)
    hub.read_script.return_value = js(PortMappingData={}, UPnP_Rules="1")
    hub.read_rules.side_effect = [snapshot, *([table("forwarding")] * 3)]
    manual = read_table("forwarding", snapshot)[1]["id"]
    result = await apply_port_rule(hub, "forwarding", {"operation": "delete", "rule_id": manual})
    assert result["status"] == "unverified" and result["dynamic_mappings_changed"] is True
    hub.write_port_rules.assert_awaited_once()


def test_dynamic_source_and_single_external_port_are_not_confused_with_empty_table():
    snapshot = table("forwarding", DYNAMIC)
    snapshot["ExternalPort"]["1"] = ""
    assert read_table("forwarding", snapshot)[0]["external_start"] == DYNAMIC["external_end"]
    snapshot = table("forwarding", FORWARD_ONE)
    snapshot.pop("RuleSource")
    with pytest.raises(InvalidResponse, match="forwarding rule's source"):
        read_table("forwarding", snapshot)
