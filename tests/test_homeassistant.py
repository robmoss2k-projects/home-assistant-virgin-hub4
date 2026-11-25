"""Optional 2026.11 Core smoke test with a synthetic Hub snapshot."""

from asyncio import Event, create_task, sleep, wait_for
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import shutil
from unittest.mock import AsyncMock

import pytest


@pytest.mark.asyncio
async def test_config_entry_entities_and_cached_action(tmp_path, monkeypatch):
    pytest.importorskip("homeassistant.core")
    from homeassistant import auth, loader
    from homeassistant.bootstrap import async_load_base_functionality
    from homeassistant.config_entries import ConfigEntries, ConfigEntryState
    from homeassistant.core import Context, HomeAssistant
    from homeassistant.exceptions import ServiceValidationError
    from homeassistant.helpers.selector import selector
    from homeassistant.helpers.service import async_get_all_descriptions

    from custom_components.virgin_hub4 import config_flow, coordinator
    from custom_components.virgin_hub4.const import CONF_EXTENDED, CONF_INTERVAL, CONF_MANAGEMENT
    from custom_components.virgin_hub4.parser import Snapshot

    # Running this test never uses the household Home Assistant or real Hub.
    path = Path(coordinator.__file__).parent
    shutil.copytree(
        path,
        tmp_path / "custom_components" / "virgin_hub4",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    hass = HomeAssistant(str(tmp_path))
    hass.config.skip_pip = True
    hass.config_entries = ConfigEntries(hass, {})
    loader.async_setup(hass)
    await loader.async_get_custom_components(hass)
    assert await async_load_base_functionality(hass)
    hass.auth = await auth.auth_manager_from_config(hass, [], [])
    sample = Snapshot(
        {
            "home": {"24g_stat": "Up", "5g_stat": "Up", "24g_guest": "false"},
            "device": {
                "cmMac": "02:00:00:00:00:01",
                "hwVersion": "11",
                "swVersion": "fixture-firmware",
                "systemUptime": "0 days 2h:0m:3s",
            },
            "line": {
                "provisioningState": "6",
                "docsisVersion": "3.1",
                "networkAccess": "true",
                "acquiredDownstreamChannelStatus": "Locked",
            },
            "mode": {"RouterMode": "5"},
            "channels": {
                "downstream_sc_qam": [
                    {
                        "channel_id": "25",
                        "lock": "Locked",
                        "snr_db": 37.5,
                        "power_dbmv": 2.0,
                    }
                ]
            },
            "events": [
                {
                    "_fingerprint": "synthetic-event",
                    "source": "docsis",
                    "priority": "6",
                    "router_time": "Mon 23/11/2026 00:43:18",
                    "category": "firmware_download_succeeded",
                }
            ],
        },
        {},
        datetime(2026, 11, 23, 12, tzinfo=timezone.utc),
    )
    mock = AsyncMock(return_value=sample)
    monkeypatch.setattr(config_flow, "collect", mock)
    monkeypatch.setattr(coordinator, "collect", mock)
    mock_setting = AsyncMock(return_value={"status": "unchanged", "group": "light_ring"})
    monkeypatch.setattr(coordinator, "apply_setting", mock_setting)
    events = []
    from homeassistant.core import callback

    @callback
    def record_event(event):
        events.append(event.data["category"])

    hass.bus.async_listen("virgin_hub4_log_event", record_event)
    try:
        result = await hass.config_entries.flow.async_init(
            "virgin_hub4",
            context={"source": "user"},
            data={"host": "192.168.0.1", "password": "synthetic"},
        )
        assert result["type"] == "create_entry"
        await hass.async_block_till_done()
        entry = result["result"]
        assert entry.state is ConfigEntryState.LOADED
        assert hass.states.get("binary_sensor.virgin_media_hub_4_cable_modem_online").state == "on"
        assert hass.states.get("sensor.virgin_media_hub_4_firmware").state == "fixture-firmware"

        with pytest.raises(ServiceValidationError):
            await hass.services.async_call(
                "virgin_hub4",
                "get_snapshot",
                {"group": "channels"},
                blocking=True,
                return_response=True,
            )
        user = await hass.auth.async_create_user("Test owner", group_ids=["system-admin"])
        data = await hass.services.async_call(
            "virgin_hub4",
            "get_snapshot",
            {"group": "events"},
            blocking=True,
            return_response=True,
            context=Context(user_id=user.id),
        )
        assert data["data"]["events"][0]["category"] == "firmware_download_succeeded"
        assert data["management_enabled"] is False
        assert "_fingerprint" not in data["data"]["events"][0]
        assert mock.await_count == 2  # UI validation and initial poll, not the cached action.
        assert all(call.kwargs["extended"] is False for call in mock.await_args_list)
        with pytest.raises(ServiceValidationError):
            await hass.services.async_call(
                "virgin_hub4",
                "set_light_ring",
                {"mode": "manual", "brightness": 15},
                blocking=True,
                return_response=True,
            )
        mock_setting.assert_not_awaited()
        with pytest.raises(ServiceValidationError, match="read-only"):
            await hass.services.async_call(
                "virgin_hub4",
                "set_light_ring",
                {"mode": "manual", "brightness": 15},
                blocking=True,
                return_response=True,
                context=Context(user_id=user.id),
            )
        mock_setting.assert_not_awaited()
        mock_setting.return_value = {"status": "read", "rules": []}
        assert (
            await hass.services.async_call(
                "virgin_hub4",
                "mac_filter_rule",
                {"operation": "list"},
                blocking=True,
                return_response=True,
                context=Context(user_id=user.id),
            )
        )["status"] == "read"
        mock_setting.assert_awaited_once_with(
            "192.168.0.1",
            "synthetic",
            "mac_rules",
            {"operation": "list"},
            expected_identity=entry.unique_id,
        )
        mock_setting.reset_mock()
        mock_setting.return_value = {"status": "unchanged", "group": "light_ring"}
        owner = entry.runtime_data
        poll_count = mock.await_count
        hass.config_entries.async_update_entry(entry, options={CONF_MANAGEMENT: True})
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert entry.runtime_data is owner and mock.await_count == poll_count
        hass.config_entries.async_update_entry(
            entry, options={CONF_MANAGEMENT: True, CONF_EXTENDED: True, CONF_INTERVAL: 7}
        )
        await hass.async_block_till_done()
        assert entry.runtime_data is owner and owner.update_interval.total_seconds() == 420
        assert mock.await_count == poll_count + 1 and mock.await_args.kwargs["extended"] is True
        outcome = await hass.services.async_call(
            "virgin_hub4",
            "set_light_ring",
            {"mode": "manual", "brightness": 15},
            blocking=True,
            return_response=True,
            context=Context(user_id=user.id),
        )
        assert outcome["status"] == "unchanged"
        mock_setting.assert_awaited_once_with(
            "192.168.0.1",
            "synthetic",
            "light_ring",
            {"mode": "manual", "brightness": 15},
            expected_identity=entry.unique_id,
        )
        mock_setting.reset_mock(return_value=True)
        mock_setting.return_value = {"status": "verified", "group": "ip_filter_schedule"}
        schedule = {"mode": "weekly", "periods": [{"day": "mon", "start": 8, "end": 11}]}
        descriptions = (await async_get_all_descriptions(hass))["virgin_hub4"]
        for service, fields in {
            "set_wifi_security": ("band24_passphrase", "band50_passphrase"),
            "set_guest_wifi": ("passphrase",),
            "set_guest_wifi_schedule": ("passphrase",),
        }.items():
            for field in fields:
                config = descriptions[service]["fields"][field]["selector"]
                assert config["text"]["type"] == "password"
                assert not descriptions[service]["fields"][field].get("required", False)
                assert selector(config)("SyntheticCredential9!") == "SyntheticCredential9!"
        for service, description in descriptions.items():
            if (config := description.get("fields", {}).get("edits")) is not None:
                edit = [{"rule_id": "fixture", "delete": True}]
                assert selector(config["selector"])(edit) == edit, service
        assert not hass.services.has_service("virgin_hub4", "change_admin_password")
        for service in ("set_mac_filter_schedule", "set_ip_filter_schedule"):
            period_selector = selector(descriptions[service]["fields"]["periods"]["selector"])
            assert period_selector(schedule["periods"]) == schedule["periods"]
        outcome = await hass.services.async_call(
            "virgin_hub4",
            "set_ip_filter_schedule",
            schedule,
            blocking=True,
            return_response=True,
            context=Context(user_id=user.id),
        )
        assert outcome["status"] == "verified"
        mock_setting.assert_awaited_once_with(
            "192.168.0.1",
            "synthetic",
            "ip_filter_schedule",
            schedule,
            expected_identity=entry.unique_id,
        )
        assert (
            selector(descriptions["ip_filter_rule"]["fields"]["family"]["selector"])("ipv6")
            == "ipv6"
        )
        mock_setting.reset_mock(return_value=True)
        mock_setting.return_value = {"status": "read", "family": "ipv6", "rules": []}
        query = {"family": "ipv6", "operation": "list"}
        outcome = await hass.services.async_call(
            "virgin_hub4",
            "ip_filter_rule",
            query,
            blocking=True,
            return_response=True,
            context=Context(user_id=user.id),
        )
        assert outcome["status"] == "read"
        mock_setting.assert_awaited_once_with(
            "192.168.0.1", "synthetic", "ip_rules", query, expected_identity=entry.unique_id
        )
        security = descriptions["set_wifi_security"]["fields"]["band24_security"]
        assert selector(security["selector"])("4") == "4"
        band = descriptions["wifi_mac_access_rule"]["fields"]["band"]
        assert selector(band["selector"])("both") == "both"
        mock_setting.reset_mock(return_value=True)
        mock_setting.return_value = {"status": "unchanged"}
        change = {"band24_security": "4", "policy": "deny_list"}
        assert (
            await hass.services.async_call(
                "virgin_hub4",
                "set_wifi_security",
                change,
                blocking=True,
                return_response=True,
                context=Context(user_id=user.id),
            )
        )["status"] == "unchanged"
        mock_setting.assert_awaited_once_with(
            "192.168.0.1", "synthetic", "wifi_settings", change, expected_identity=entry.unique_id
        )
        assert (
            selector(descriptions["set_dhcp_ipv6"]["fields"]["mode"]["selector"])("stateful")
            == "stateful"
        )
        mock_setting.reset_mock(return_value=True)
        mock_setting.return_value = {"status": "read", "reservations": []}
        request = {"operation": "list"}
        outcome = await hass.services.async_call(
            "virgin_hub4",
            "dhcp_reservation",
            request,
            blocking=True,
            return_response=True,
            context=Context(user_id=user.id),
        )
        assert outcome["status"] == "read"
        mock_setting.assert_awaited_once_with(
            "192.168.0.1",
            "synthetic",
            "dhcp_reservations",
            request,
            expected_identity=entry.unique_id,
        )
        assert (
            selector(descriptions["get_network_test_status"]["fields"]["test"]["selector"])("ping")
            == "ping"
        )
        entered = Event()

        async def wait_to_cancel(host, password, group, fields, *, cancel, expected_identity):
            assert group == "ping_test"
            assert expected_identity == entry.unique_id
            entered.set()
            await cancel.wait()
            return {"status": "canceled"}

        mock_setting.side_effect = wait_to_cancel
        run = create_task(
            hass.services.async_call(
                "virgin_hub4",
                "run_ping",
                {"target": "192.0.2.1"},
                blocking=True,
                return_response=True,
                context=Context(user_id=user.id),
            )
        )
        await wait_for(entered.wait(), timeout=2)
        old_owner = entry.runtime_data

        async def wait_until_draining(owner):
            while not owner._closing:
                await sleep(0)

        reload = create_task(hass.config_entries.async_reload(entry.entry_id))
        try:
            await wait_for(wait_until_draining(old_owner), timeout=2)
            assert entry.state is ConfigEntryState.UNLOAD_IN_PROGRESS and not reload.done()
            cancel = await hass.services.async_call(
                "virgin_hub4",
                "cancel_network_diagnostic",
                {},
                blocking=True,
                return_response=True,
                context=Context(user_id=user.id),
            )
            assert cancel == {"status": "cancel_requested"}
            assert await wait_for(run, timeout=2) == {"status": "canceled"}
            assert await wait_for(reload, timeout=5)
            assert entry.runtime_data is not old_owner
        finally:
            if not run.done():
                run.cancel()
            if not reload.done():
                reload.cancel()
        mock_setting.side_effect = None
        mock_setting.reset_mock()
        mock_setting.return_value = {"status": "verified", "label": ""}
        label = {"mac": "02:00:00:00:00:01", "label": ""}
        assert (
            await hass.services.async_call(
                "virgin_hub4",
                "set_connected_device_name",
                label,
                blocking=True,
                return_response=True,
                context=Context(user_id=user.id),
            )
        )["status"] == "verified"
        mock_setting.assert_awaited_once_with(
            "192.168.0.1", "synthetic", "device_label", label, expected_identity=entry.unique_id
        )
        mock_setting.reset_mock()
        mock_setting.return_value = {
            "status": "read",
            "mode": "router",
            "identity": entry.unique_id,
        }
        plan = await hass.services.async_call(
            "virgin_hub4",
            "prepare_operating_mode_change",
            {"mode": "modem"},
            blocking=True,
            return_response=True,
            context=Context(user_id=user.id),
        )
        assert (
            plan["status"] == "prepared" and plan["expected_management_address"] == "192.168.100.1"
        )
        mock_setting.assert_awaited_once_with(
            "192.168.0.1", "synthetic", "mode_state", {"for_switch": True}
        )
        apply_args = {"plan_id": plan["plan_id"], "confirm_local_recovery": False}
        with pytest.raises(ServiceValidationError, match="local recovery"):
            await hass.services.async_call(
                "virgin_hub4",
                "apply_operating_mode_change",
                apply_args,
                blocking=True,
                return_response=True,
                context=Context(user_id=user.id),
            )
        mock_setting.reset_mock()
        mock_setting.return_value = {"status": "submission_uncertain"}
        apply_args["confirm_local_recovery"] = True
        switched = await hass.services.async_call(
            "virgin_hub4",
            "apply_operating_mode_change",
            apply_args,
            blocking=True,
            return_response=True,
            context=Context(user_id=user.id),
        )
        assert switched["status"] == "submission_uncertain"
        assert entry.data["host"] == "192.168.0.1"
        with pytest.raises(ServiceValidationError, match="No operating mode change is prepared"):
            await hass.services.async_call(
                "virgin_hub4",
                "apply_operating_mode_change",
                apply_args,
                blocking=True,
                return_response=True,
                context=Context(user_id=user.id),
            )
        mock_setting.assert_awaited_once_with(
            "192.168.0.1",
            "synthetic",
            "mode_submit",
            {"identity": entry.unique_id, "current_mode": "router", "target_mode": "modem"},
        )
        assert events == []  # Initial historical rows are not replayed.
        newest = sample.groups["events"][0] | {
            "category": "t3_timeout",
            "_fingerprint": "new-event",
        }
        mock.return_value = replace(
            sample,
            groups=sample.groups | {"events": [newest, *sample.groups["events"]]},
        )
        await entry.runtime_data.async_refresh()
        await entry.runtime_data.async_refresh()
        await hass.async_block_till_done()
        assert events == ["t3_timeout"]

        original_entity_ids = {
            state.entity_id
            for state in hass.states.async_all()
            if "virgin_media_hub_4" in state.entity_id
        }
        original_connection = entry.data
        for working in ("read", "write"):
            entered, release = Event(), Event()
            old_owner = entry.runtime_data

            async def hold(*args, **kwargs):
                entered.set()
                await release.wait()
                return mock.return_value if working == "read" else {"status": "verified"}

            if working == "read":
                mock.side_effect = hold
                active = create_task(old_owner.async_refresh())
            else:
                mock_setting.side_effect = hold
                active = create_task(
                    hass.services.async_call(
                        "virgin_hub4",
                        "set_guest_wifi",
                        {"ssid": "Synthetic"},
                        blocking=True,
                        return_response=True,
                        context=Context(user_id=user.id),
                    )
                )
            reload = None
            try:
                await wait_for(entered.wait(), timeout=2)
                poll_count = mock.await_count
                reload = create_task(hass.config_entries.async_reload(entry.entry_id))
                await wait_for(wait_until_draining(old_owner), timeout=2)
                assert not reload.done() and not active.done()
                assert entry.runtime_data is old_owner and mock.await_count == poll_count
                release.set()
                result = await wait_for(active, timeout=2)
                if working == "write":
                    assert result == {"status": "verified"}
                assert await wait_for(reload, timeout=5)
                assert entry.runtime_data is not old_owner and mock.await_count == poll_count + 1
            finally:
                release.set()
                mock.side_effect = mock_setting.side_effect = None
                if not active.done():
                    active.cancel()
                if reload is not None and not reload.done():
                    reload.cancel()
        assert entry.data is original_connection
        assert {
            state.entity_id
            for state in hass.states.async_all()
            if "virgin_media_hub_4" in state.entity_id
        } == original_entity_ids

        assert await hass.config_entries.async_unload(entry.entry_id)
        assert entry.state is ConfigEntryState.NOT_LOADED
    finally:
        await hass.async_stop(force=True)
