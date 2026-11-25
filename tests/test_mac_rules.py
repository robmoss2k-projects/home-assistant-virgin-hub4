"""Offline MAC filter contract and guardrail tests."""

from unittest.mock import AsyncMock

import pytest

from custom_components.virgin_hub4.mac_rules import apply_mac_rule, read_mac_table

MAC_A = "02:00:00:00:00:11"
MAC_B = "02:00:00:00:00:12"
ROW_A = ["test-a", MAC_A, "true"]
ROW_B = ["test-b", MAC_B, "false"]


def table(*rows):
    return {"numberOfMACList": {"1": len(rows)}, **{str(i): row for i, row in enumerate(rows)}}


async def test_mac_add_matches_portal_contract_and_does_not_rewrite_neighbour():
    hub = AsyncMock()
    hub.read_mac_rules.side_effect = [table(ROW_B), table(ROW_A, ROW_B)]
    result = await apply_mac_rule(
        hub, {"operation": "add", "mac": "02-00-00-00-00-11", "name": "test-a"}
    )
    assert result["status"] == "verified"
    hub.write_mac_rules.assert_awaited_once_with(
        {
            "NewFilterDevice": [{"HostName": "test-a", "MACAddress": MAC_A, "Enable": "true"}],
        }
    )


async def test_mac_delete_disables_deleted_row_but_preserves_enabled_neighbour():
    hub = AsyncMock()
    enabled_b = ["test-b", MAC_B, "true"]
    hub.read_mac_rules.side_effect = [table(ROW_A, enabled_b), table(enabled_b)]
    result = await apply_mac_rule(hub, {"operation": "delete", "mac": MAC_A})
    assert result["status"] == "verified"
    hub.write_mac_rules.assert_awaited_once_with(
        {
            "EditFilterDevice": [{"DeleteData": [0, -1], "EnableData": [-1, 1]}],
        }
    )


async def test_mac_duplicate_or_missing_edit_cannot_target_the_wrong_row():
    hub = AsyncMock()
    hub.read_mac_rules.return_value = table(ROW_A, ROW_A)
    with pytest.raises(ValueError, match="multiple rules"):
        await apply_mac_rule(hub, {"operation": "set_enabled", "mac": MAC_A, "enabled": False})
    hub.write_mac_rules.assert_not_awaited()
    assert read_mac_table(table()) == []
