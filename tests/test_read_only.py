"""Pilot gates do not rely on hiding Home Assistant actions."""

from asyncio import Lock, create_task, sleep
from types import SimpleNamespace
from unittest.mock import AsyncMock

from homeassistant.const import CONF_HOST, CONF_PASSWORD
import pytest

from custom_components.virgin_hub4 import coordinator
from custom_components.virgin_hub4.client import SessionBusy
from custom_components.virgin_hub4.const import CONF_MANAGEMENT
from custom_components.virgin_hub4.controls import InvalidSetting
from custom_components.virgin_hub4.permissions import requires_management


@pytest.mark.parametrize(
    "group",
    ["dhcp_reservations", "ip_rules", "mac_rules", "wifi_access_list", "forwarding", "triggering"],
)
def test_rule_actions_require_management_unless_reading_table(group):
    assert not requires_management(group, {"operation": "list"})
    for value in ("add", "delete", "set_enabled", "apply", None):
        assert requires_management(group, {"operation": value})


def test_read_only_configuration_blocks_new_actions_and_active_diagnostics():
    assert requires_management("new_unclassified_action", {"operation": "list"})
    for group in ("mode_prepare", "mode_execute", "ping_test", "trace_test", "diagnostic_wizard"):
        assert requires_management(group, {})
    for group in ("portal_language_read", "mode_state", "guest_schedule_read", "diagnostic_status"):
        assert not requires_management(group, {})


@pytest.mark.asyncio
async def test_queued_write_does_not_survive_a_management_revocation(monkeypatch):
    entry = SimpleNamespace(data={}, options={CONF_MANAGEMENT: True})
    hub = object.__new__(coordinator.HubCoordinator)
    hub._entry = entry
    hub._connection = entry.data
    hub._closing = False
    hub._session_lock = Lock()
    write = AsyncMock()
    monkeypatch.setattr(coordinator, "apply_setting", write)
    async with hub._session_lock:
        task = create_task(hub.async_apply_setting("upnp", {"enabled": True}))
        await sleep(0)
        assert not task.done()
        entry.options = {}
    with pytest.raises(InvalidSetting, match="read-only"):
        await task
    write.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["verified", "not_applied", "outcome_unknown"])
async def test_guest_update_does_not_trigger_an_extra_login(monkeypatch, status):
    hub = object.__new__(coordinator.HubCoordinator)
    hub._entry = SimpleNamespace(
        data={CONF_HOST: "192.168.0.1", CONF_PASSWORD: "fixture-password"},
        options={CONF_MANAGEMENT: True},
        unique_id="fixture-id",
    )
    hub._session_lock = Lock()
    hub.async_request_refresh = AsyncMock()
    hub._connection = hub._entry.data
    hub._closing = False
    result = {"status": status, "group": "guest"}
    apply = AsyncMock(return_value=result)
    monkeypatch.setattr(coordinator, "apply_setting", apply)
    assert await hub.async_apply_setting("guest", {"ssid": "Fixture"}) == result
    apply.assert_awaited_once()
    hub.async_request_refresh.assert_not_awaited()


@pytest.mark.parametrize("status,refreshes", [("unverified", 0), ("verified", 1)])
async def test_only_verified_port_rule_write_triggers_a_post_action_refresh(
    monkeypatch, status, refreshes
):
    hub = object.__new__(coordinator.HubCoordinator)
    hub._entry = SimpleNamespace(
        data={CONF_HOST: "192.168.0.1", CONF_PASSWORD: "fixture-password"},
        options={CONF_MANAGEMENT: True},
        unique_id="fixture-id",
    )
    hub._session_lock = Lock()
    hub.async_request_refresh = AsyncMock()
    hub._connection = hub._entry.data
    hub._closing = False
    result = {"status": status, "rules": []}
    apply = AsyncMock(return_value=result)
    monkeypatch.setattr(coordinator, "apply_setting", apply)
    assert await hub.async_apply_setting("forwarding", {"operation": "delete"}) == result
    assert hub.async_request_refresh.await_count == refreshes
    apply.assert_awaited_once()


@pytest.mark.asyncio
async def test_drain_timeout_refuses_unload_without_cancelling_active_operation(monkeypatch):
    hub = object.__new__(coordinator.HubCoordinator)
    hub._entry = SimpleNamespace(data={})
    hub._connection = hub._entry.data
    hub._session_lock = Lock()
    hub._closing = False
    monkeypatch.setattr(coordinator, "_UNLOAD_WAIT_SECONDS", 0.01)
    async with hub.async_session_scope():
        drain = create_task(hub.async_drain())
        await sleep(0)
        with pytest.raises(SessionBusy, match="unloading"):
            async with hub.async_session_scope():
                pytest.fail("A new operation was admitted during unload")
        assert not await drain
        assert hub._session_lock.locked() and not hub._closing
    assert await hub.async_drain()
