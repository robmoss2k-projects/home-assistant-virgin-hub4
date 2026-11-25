"""Regressions for the whole-portal audit. All replies are synthetic."""

from asyncio import Event
from copy import deepcopy
import json
from unittest.mock import call

import pytest

from custom_components.virgin_hub4 import controls, network_tests, verification
from custom_components.virgin_hub4.client import (
    CannotConnect,
    HubClient,
    SessionCrypto,
    SessionExpired,
)
from custom_components.virgin_hub4.ip_rules import _overlap
from custom_components.virgin_hub4.mac_rules import _plan as mac_plan
from custom_components.virgin_hub4.port_rules import _plan_add, read_table
from custom_components.virgin_hub4.portal import Provisioning, passphrase, ssid
from test_client import FakeHttp, LOGIN, MODE, RADIOS, encrypted_reply, fixture_hub
from test_dhcp import SETTINGS as DHCP_SETTINGS
from test_dhcp import clients, fragment
from test_guest_schedule import TIMER, WIFI
from test_ip_rules import V4, V6, row
from test_ip_rules import table as ip_table
from test_modem_mode import DEVICE, IDENTITY
from test_parser import js
from test_port_rules import DYNAMIC, FORWARD_ONE, FORWARD_TWO, TRIGGER_ONE, TRIGGER_TWO
from test_port_rules import table as port_table
from test_wireless import ENTRY, SETTINGS, list_reply

NEW_PRIMARY = "SyntheticNew7!"
NEW_GUEST = "NewGuestFixture4!"


def decoded(http, path, field):
    matches = [options for route, options in http.requests if route == path]
    assert len(matches) == 1
    value = json.loads(matches[0]["data"][field])
    login = json.loads(http.requests[1][1]["data"]["configInfo"])
    assert value["iv"] != login["iv"]
    assert NEW_PRIMARY not in json.dumps(value) and NEW_GUEST not in json.dumps(value)
    return SessionCrypto.from_password("fixture-pass", salt=login["salt"]).open_response(
        value, value
    )


async def test_primary_explicit_rotation_encrypts_and_checks_the_other_keys():
    after = deepcopy(SETTINGS)
    after["Configuration"][0]["Passphrase"] = NEW_PRIMARY
    http = FakeHttp(
        MODE,
        LOGIN,
        encrypted_reply(SETTINGS),
        json.dumps(list_reply(ENTRY)),
        RADIOS,
        encrypted_reply(WIFI),
        "",
        encrypted_reply(after),
        json.dumps(list_reply(ENTRY)),
        encrypted_reply(WIFI),
        "",
    )
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    result = await controls.apply_owned_session(
        hub, "wifi_settings", {"band24_passphrase": NEW_PRIMARY}
    )
    assert result["status"] == "verified" and "SyntheticNew" not in repr(result)
    assert "fixture&one" not in repr(result) and "fixture-two" not in repr(result)
    assert await hub.logout()
    wire = decoded(http, "/php/ajaxSet_wifi_settings_data.php", "wifiData")["Configuration"]
    assert wire["bssIdxWPAPresharedKey"] == NEW_PRIMARY
    assert wire["bssIdxWPAPresharedKey50"] == SETTINGS["Configuration"][1]["Passphrase"]


async def test_linked_names_rotate_both_bands_without_a_second_write():
    hub = fixture_hub()
    linked = deepcopy(SETTINGS)
    linked["Configuration"][1] = linked["Configuration"][0].copy()
    after = deepcopy(linked)
    for band in after["Configuration"]:
        band["Passphrase"] = NEW_PRIMARY
    hub.read_wifi.side_effect = [linked, WIFI, after, WIFI]
    hub.read_rules.return_value = list_reply(ENTRY)
    assert (
        await controls.apply_owned_session(
            hub,
            "wifi_settings",
            {"band24_passphrase": NEW_PRIMARY},
        )
    )["status"] == "verified"
    hub.write_wifi_settings.assert_awaited_once()
    config = hub.write_wifi_settings.await_args.args[0]["Configuration"]
    assert config["bssIdxWPAPresharedKey"] == config["bssIdxWPAPresharedKey50"] == NEW_PRIMARY


async def test_guest_explicit_key_is_encrypted_and_read_back_without_exposing_it(monkeypatch):
    monkeypatch.setattr(controls, "_GUEST_POLL_SECONDS", 0)
    http = FakeHttp(
        MODE,
        LOGIN,
        encrypted_reply(WIFI),
        RADIOS,
        "",
        encrypted_reply(WIFI | {"passphrase": NEW_GUEST}),
        "",
    )
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-pass")
    result = await controls.apply_owned_session(hub, "guest", {"passphrase": NEW_GUEST})
    assert result["status"] == "verified" and result["reported_passphrase_verified"] is True
    assert NEW_GUEST not in repr(result)
    assert await hub.logout()
    assert decoded(http, "/php/ajaxSet_guest_settings.php", "gnData")["passphrase"] == NEW_GUEST


async def test_guest_rotation_does_not_count_masked_readback_as_verified(monkeypatch):
    monkeypatch.setattr(controls, "_GUEST_READBACK_SECONDS", 0)
    hub = fixture_hub()
    hub.read_wifi.side_effect = [WIFI, WIFI | {"passphrase": "*" * len(NEW_GUEST)}]
    result = await controls.apply_owned_session(hub, "guest", {"passphrase": NEW_GUEST})
    assert result["status"] == "outcome_unknown"
    assert NEW_GUEST not in repr(result)
    hub.write_guest.assert_awaited_once()


async def test_guest_wizard_updates_name_key_and_timer_in_one_write(monkeypatch):
    from datetime import datetime, timezone

    monkeypatch.setattr(
        "custom_components.virgin_hub4.guest_schedule._now",
        lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    hub = fixture_hub()
    names = {"NetworkName": "New Fixture", "GuestWizPassphrase": NEW_GUEST}
    hub.read_wifi.side_effect = [
        TIMER,
        WIFI,
        TIMER | names | {"ActiveTimeout": "24/11/2026-18:30"},
        WIFI | {"ssid": "New Fixture", "passphrase": NEW_GUEST},
    ]
    reply = await controls.apply_owned_session(
        hub,
        "guest_schedule",
        {
            "ssid": "New Fixture",
            "passphrase": NEW_GUEST,
            "mode": "until",
            "expires_at": "2026-11-24 18:30",
        },
    )
    assert reply["status"] == "recorded" and NEW_GUEST not in repr(reply)
    hub.write_guest_schedule.assert_awaited_once()
    assert (
        hub.write_guest_schedule.await_args.args[0] | names
        == hub.write_guest_schedule.await_args.args[0]
    )


async def test_radios_down_and_primary_guest_collision_block_writes():
    hub = fixture_hub()
    hub.read_script.return_value = js(**{"24g_stat": "LowerLayerDown", "5g_stat": "Down"})
    hub.read_wifi.return_value = WIFI
    with pytest.raises(controls.InvalidSetting, match="at least one active radio"):
        await controls.apply_owned_session(hub, "guest", {"ssid": "New Guest"})
    hub.read_script.return_value = RADIOS
    hub.read_wifi.return_value = WIFI | {"24Passphrase": NEW_GUEST}
    with pytest.raises(controls.InvalidSetting, match="must not share"):
        await controls.apply_owned_session(hub, "guest", {"passphrase": NEW_GUEST})
    hub.write_guest.assert_not_awaited()


def test_ssid_and_strength_boundaries():
    for name in (" Leading", "Trailing ", "Virgin Media", "Ziggo", "é" * 17):
        with pytest.raises(ValueError):
            ssid(name)
    assert ssid("Ordinary Name") == "Ordinary Name"
    assert passphrase("LongMixedCasePassphraseWithoutDigits", open_network=False, conflicting=())
    with pytest.raises(ValueError, match="portal-valid"):
        passphrase("tooWeak", open_network=False, conflicting=())


@pytest.mark.parametrize("group", ["forwarding", "triggering", "upnp", "dmz"])
async def test_ds_lite_hidden_controls_never_send(group):
    hub = fixture_hub()
    hub.read_portal_provisioning.return_value = Provisioning("2", "1")
    change = {"operation": "add"} if group in {"forwarding", "triggering"} else {"enabled": True}
    with pytest.raises(controls.InvalidSetting, match="portal hides"):
        await controls.apply_owned_session(hub, group, change)
    hub.write_port_rules.assert_not_awaited()
    hub.write_dmz.assert_not_awaited()
    hub.write_upnp.assert_not_awaited()


async def test_ip_filter_bounds_capacity_overlap_and_hidden_families():
    hub = fixture_hub()
    hub.read_script.return_value = ip_table(v4=[row(V4)])
    change = {
        "family": "ipv4",
        "operation": "add",
        "protocol": "BOTH",
        "source": "192.0.2.11-192.0.2.12",
        "destination": "any",
        "source_port_start": 999,
        "source_port_end": 1002,
        "destination_port_start": 443,
        "destination_port_end": 443,
        "enabled": True,
    }
    with pytest.raises(controls.InvalidSetting, match="overlaps"):
        await controls.apply_owned_session(hub, "ip_rules", change)
    with pytest.raises(controls.InvalidSetting, match="advertised range"):
        await controls.apply_owned_session(hub, "ip_rules", change | {"source": "192.0.2.1"})
    hub.read_script.return_value = ip_table(
        v4=[
            row(V4 | {"SrcStartAddr": f"192.0.2.{i}", "SrcEndAddr": "0.0.0.0"}, key=str(i))
            for i in range(30, 62)
        ]
    )
    with pytest.raises(controls.InvalidSetting, match="up to 32"):
        await controls.apply_owned_session(hub, "ip_rules", change)
    hub.read_ip_provisioning.return_value = frozenset({"v4"})
    with pytest.raises(controls.InvalidSetting, match="portal hides"):
        await controls.apply_owned_session(hub, "ip_rules", change | {"family": "ipv6"})
    hub.add_ip_rule.assert_not_awaited()


def test_ip_filter_ui_tests_containment_for_ipv4_but_overlap_for_ipv6():
    row = {
        "source": "any",
        "destination": "any",
        "protocol": "TCP",
        "direction": "outgoing",
        "source_port_start": 1000,
        "source_port_end": 1001,
        "destination_port_start": 443,
        "destination_port_end": 443,
    }
    partial = row | {"source_port_start": 1001, "source_port_end": 1002}
    enclosing = row | {"source_port_start": 999, "source_port_end": 1002}
    adjacent = row | {"source_port_start": 1002, "source_port_end": 1003}
    assert not _overlap(partial, row, ip6=False)
    assert _overlap(partial, row, ip6=True)
    assert all(_overlap(enclosing, row, ip6=family) for family in (False, True))
    assert not any(_overlap(adjacent, row, ip6=family) for family in (False, True))


def test_port_and_mac_table_caps_and_noop_at_limit():
    for group, prefix in (
        ("forwarding", ("local", "external")),
        ("triggering", ("trigger", "forward")),
    ):
        base = {"protocol": "TCP", "enabled": True} | (
            {"target": "192.0.2.10"} if group == "forwarding" else {}
        )
        items = [
            base | {f"{p}_{e}": 20000 + i for p in prefix for e in ("start", "end")}
            for i in range(33)
        ]
        rows = [_plan_add(group, item, [])[0] for item in items[:32]]
        assert _plan_add(group, items[0], rows)[1] == {}
        with pytest.raises(ValueError, match="32"):
            _plan_add(group, items[-1], rows)
    rows = [
        {"mac": f"02:00:00:00:00:{i:02x}", "name": f"Device {i}", "enabled": True}
        for i in range(32)
    ]
    with pytest.raises(ValueError, match="32"):
        mac_plan("add", {"mac": "02:00:00:00:01:01", "name": "New device"}, rows)


async def test_port_batch_plans_all_ids_before_one_mixed_table_apply():
    hub = fixture_hub()
    before = port_table("forwarding", FORWARD_ONE, DYNAMIC, FORWARD_TWO)
    after = port_table("forwarding", DYNAMIC, FORWARD_TWO | {"enabled": False})
    hub.read_rules.return_value = before
    hub.read_script.return_value = js(PortMappingData={}, UPnP_Rules="1")
    left, dynamic, right = read_table("forwarding", before)
    edits = [{"rule_id": left["id"], "delete": True}, {"rule_id": right["id"], "enabled": False}]
    with pytest.raises(controls.InvalidSetting, match="not manual"):
        await controls.apply_owned_session(
            hub,
            "forwarding",
            {"operation": "apply", "edits": edits + [{"rule_id": dynamic["id"], "delete": True}]},
        )
    hub.write_port_rules.assert_not_awaited()
    hub.read_rules.side_effect = [before, after]
    result = await controls.apply_owned_session(
        hub, "forwarding", {"operation": "apply", "edits": edits}
    )
    assert result["status"] == "verified"
    hub.write_port_rules.assert_awaited_once_with(
        "forwarding",
        {"Enable": [0, -1], "Delete": [0, -1]},
        add=False,
    )


async def test_trigger_batch_can_enable_one_row_and_delete_another_once():
    hub = fixture_hub()
    before = port_table("triggering", TRIGGER_ONE, TRIGGER_TWO)
    after = port_table("triggering", TRIGGER_TWO | {"enabled": True})
    hub.read_rules.side_effect = [before, after]
    left, right = read_table("triggering", before)
    result = await controls.apply_owned_session(
        hub,
        "triggering",
        {
            "operation": "apply",
            "edits": [
                {"rule_id": left["id"], "delete": True},
                {"rule_id": right["id"], "enabled": True},
            ],
        },
    )
    assert result["status"] == "verified"
    hub.write_port_rules.assert_awaited_once_with(
        "triggering", {"Enable": [0, 1], "Delete": [0, -1]}, add=False
    )


async def test_mixed_ip_batch_stops_on_first_ambiguous_row(monkeypatch):
    monkeypatch.setattr(verification, "READBACK_SECONDS", 0)
    hub = fixture_hub()
    before = ip_table(v4=[row(V4)], v6=[row(V6, key="22")])
    partial = ip_table(v6=[row(V6, key="22")])
    hub.read_script.side_effect = [before, before, before, partial, partial]
    id4 = (
        await controls.apply_owned_session(hub, "ip_rules", {"family": "ipv4", "operation": "list"})
    )["rules"][0]["id"]
    id6 = (
        await controls.apply_owned_session(hub, "ip_rules", {"family": "ipv6", "operation": "list"})
    )["rules"][0]["id"]
    edits = [
        {"family": "ipv6", "rule_id": id6, "enabled": False},
        {"family": "ipv4", "rule_id": id4, "delete": True},
    ]
    hub.edit_ip_rule.side_effect = CannotConnect("lost acknowledgement")
    result = await controls.apply_owned_session(
        hub, "ip_rules", {"family": "both", "operation": "apply", "edits": edits}
    )
    assert result["status"] == "unverified" and result["ipv4_rules"] == []
    assert result["ipv6_rules"][0]["enabled"] is True
    hub.edit_ip_rule.assert_awaited_once_with("14", ip6=False, enabled=False, delete=True)


async def test_ip_batch_uses_fresh_firmware_keys_after_delete():
    hub = fixture_hub()
    second = V4 | {"SrcStartAddr": "192.0.2.22", "SrcEndAddr": "192.0.2.23"}
    before = ip_table(v4=[row(V4), row(second, key="15")], v6=[row(V6, key="22")])
    renumbered = ip_table(v4=[row(second, key="14")], v6=[row(V6, key="22")])
    after = ip_table(v4=[row(second, key="14", enabled="false")], v6=[row(V6, key="22")])
    hub.read_script.side_effect = [before, before, renumbered, after]
    rows = (
        await controls.apply_owned_session(hub, "ip_rules", {"family": "ipv4", "operation": "list"})
    )["rules"]
    result = await controls.apply_owned_session(
        hub,
        "ip_rules",
        {
            "family": "ipv4",
            "operation": "apply",
            "edits": [
                {"rule_id": rows[1]["id"], "enabled": False},
                {"rule_id": rows[0]["id"], "delete": True},
            ],
        },
    )
    assert result["status"] == "verified"
    assert result["rules"] == [rows[1] | {"enabled": False}]
    assert hub.edit_ip_rule.await_args_list == [
        call("14", ip6=False, enabled=False, delete=True),
        call("14", ip6=False, enabled=False, delete=False),
    ]


async def test_reservation_batch_uses_one_address_array():
    hub = fixture_hub()
    pairs = [["02:00:00:11:00:01", "192.168.0.12"], ["02:00:00:11:00:02", "192.168.0.13"]]
    hub.read_script.return_value = fragment()
    hub.read_dhcp.side_effect = [DHCP_SETTINGS, clients(*pairs), DHCP_SETTINGS, clients()]
    hub.write_dhcp.return_value = None
    edits = [{"mac": mac, "address": addr, "delete": True} for mac, addr in pairs]
    result = await controls.apply_owned_session(
        hub, "dhcp_reservations", {"operation": "apply", "edits": edits}
    )
    assert result["status"] == "verified" and not result["reservations"]
    hub.write_dhcp.assert_awaited_once_with({"setting": "delete", "delIdx": [p[1] for p in pairs]})


async def test_wireless_mac_batch_removes_multiple_band_rows_once():
    hub = fixture_hub()
    hub.read_wifi.return_value = SETTINGS
    hub.read_rules.side_effect = [list_reply(ENTRY, ENTRY | {"SSIDIndex": 2}), list_reply()]
    edits = [
        {"rule_id": f"{band}:{ENTRY['MACAddress']}", "delete": True}
        for band in ("band24", "band50")
    ]
    reply = await controls.apply_owned_session(
        hub, "wifi_access_list", {"operation": "apply", "edits": edits}
    )
    assert reply["status"] == "verified" and not reply["rules"]
    hub.write_wifi_settings.assert_awaited_once()
    assert hub.write_wifi_settings.await_args.args[0]["RemoveMacFilterDevice"] == [0, 1]


def test_router_mac_multi_row_apply_preserves_indexes():
    first = {"mac": "02:00:00:00:00:01", "name": "First", "enabled": True}
    second = {"mac": "02:00:00:00:00:02", "name": "Second", "enabled": False}
    edits = [{"mac": first["mac"], "delete": True}, {"mac": second["mac"], "enabled": True}]
    form, rows = mac_plan("apply", {"edits": edits}, [first, second])
    assert form == {"EditFilterDevice": [{"DeleteData": [0, -1], "EnableData": [-1, 1]}]}
    assert rows == [second | {"enabled": True}]


async def test_owned_wps_failure_after_settings_window_is_dismissed_once(monkeypatch):
    hub = fixture_hub()
    hub.read_script.return_value = js(WPSPbcEnable="true")
    hub.read_wps_result.return_value = {"24g": "Idle", "5g": "Idle"}
    windows = []

    async def sample(_read, **options):
        windows.append(options.get("poll_seconds"))
        yield (
            {"24g": "In progress", "5g": "In progress"}
            if len(windows) == 1
            else {"24g": "Failed", "5g": "Failed"}
        )

    monkeypatch.setattr(controls, "readback_samples", sample)
    reply = await controls.apply_owned_session(hub, "wps_registration", {})
    assert windows == [None, 30] and reply["cleanup"] == "acknowledged"
    hub.start_wps.assert_awaited_once()
    hub.clear_failed_wps.assert_awaited_once()


async def test_diagnostic_can_cancel_in_owned_grace_without_new_start(monkeypatch):
    hub = fixture_hub()
    hub.get_probe_status.side_effect = [
        {"status": "None"},
        {"status": "Running"},
        {"status": "Running"},
        {"status": "Running"},
        {"status": "Canceled"},
    ]
    tick, cancel = [0], Event()
    monkeypatch.setattr(network_tests, "monotonic", lambda: tick[0])

    async def wait(_event, _seconds):
        tick[0] += 5
        if tick[0] == 10:
            cancel.set()

    monkeypatch.setattr(network_tests, "_wait", wait)
    result = await network_tests.run_probe(
        hub, {"target": "192.0.2.1", "timeout_seconds": 5}, trace=False, cancel=cancel
    )
    assert result["status"] == "canceled"
    assert hub.set_probe.await_args_list[-1] == call({"settings": "Canceled"}, trace=False)
    assert hub.set_probe.await_count == 2


async def test_unsupported_diagnostic_target_and_ambiguous_mode_response():
    hub = fixture_hub()
    hub.read_portal_provisioning.return_value = Provisioning("1", "0")
    with pytest.raises(ValueError, match="target IP family"):
        await network_tests.run_probe(hub, {"target": "2001:db8::1"}, trace=True, cancel=Event())
    hub.set_probe.assert_not_awaited()
    for response, status in (
        ("<html>Sign in</html>", "submission_uncertain"),
        ('"0"', "submission_uncertain"),
        ('{"error":"refused"}', "rejected"),
    ):
        hub.read_script.side_effect = [js(RouterMode="5"), js(**DEVICE)]
        hub.submit_operating_mode.return_value = response
        result = await controls.apply_owned_session(
            hub,
            "mode_submit",
            {
                "identity": IDENTITY,
                "current_mode": "router",
                "target_mode": "modem",
            },
        )
        assert result["status"] == status


async def test_diagnostic_does_not_cancel_after_losing_its_session(monkeypatch):
    hub = fixture_hub()
    cancel = Event()
    hub.get_probe_status.side_effect = [
        {"status": "None"},
        {"status": "Running"},
        SessionExpired("fixture login expired"),
    ]

    async def wait(_event, _seconds):
        cancel.set()

    monkeypatch.setattr(network_tests, "_wait", wait)
    result = await network_tests.run_probe(
        hub, {"target": "192.0.2.1", "timeout_seconds": 5}, trace=False, cancel=cancel
    )
    assert result["status"] == "cancel_unverified"
    assert result["write_issue"] == "SessionExpired"
    assert hub.get_probe_status.await_count == 3
    hub.set_probe.assert_awaited_once()
