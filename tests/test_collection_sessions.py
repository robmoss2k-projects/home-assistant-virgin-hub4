"""Read-only retry and reauthentication policy; no real Hub traffic."""

from asyncio import Lock, create_task, sleep
from types import SimpleNamespace
from unittest.mock import AsyncMock

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed
import pytest

from custom_components.virgin_hub4 import collection, config_flow, coordinator
from custom_components.virgin_hub4 import client as transport
from custom_components.virgin_hub4.client import AuthenticationError, SessionBusy, SessionExpired
from custom_components.virgin_hub4.modem_mode import hub_identity
from custom_components.virgin_hub4.parser import REQUIRED_MARKERS, parse_snapshot
from test_parser import js, snapshot_inputs


def _install_sessions(monkeypatch, first, *later):
    issued = []
    source = iter((first, *later))

    class Session:
        async def __aenter__(self):
            issued.append(self)
            return self

        async def __aexit__(self, *_):
            return None

    monkeypatch.setattr(transport.aiohttp, "ClientSession", lambda **_: Session())
    monkeypatch.setattr(transport, "HubClient", lambda *_: next(source))
    return issued


@pytest.mark.asyncio
async def test_owned_read_expiry_can_recover_in_one_fresh_transaction(monkeypatch):
    old, new = AsyncMock(), AsyncMock()
    sessions = _install_sessions(monkeypatch, old, new)
    result = object()
    read = AsyncMock(side_effect=[SessionExpired("synthetic lost session"), result])
    monkeypatch.setattr(collection, "collect_owned_session", read)
    assert await collection.collect("192.168.0.1", "fixture-pass", extended=True) is result
    assert len(sessions) == 2 and sessions[0] is not sessions[1]
    old.logout.assert_awaited_once()
    new.logout.assert_awaited_once()
    assert [call.args[0] for call in read.await_args_list] == [old, new]


@pytest.mark.asyncio
async def test_recovery_respects_browser_taking_the_session_in_between(monkeypatch):
    old, new = AsyncMock(), AsyncMock()
    sessions = _install_sessions(monkeypatch, old, new)
    read = AsyncMock(side_effect=SessionExpired("synthetic lost session"))
    monkeypatch.setattr(collection, "collect_owned_session", read)
    new.login.side_effect = SessionBusy("browser owns the session")
    with pytest.raises(SessionBusy):
        await collection.collect("192.168.0.1", "fixture-pass", extended=True)
    assert len(sessions) == 2
    old.logout.assert_awaited_once()
    new.logout.assert_not_awaited()
    read.assert_awaited_once()


@pytest.mark.parametrize("exception", [AuthenticationError, SessionBusy, SessionExpired])
@pytest.mark.asyncio
async def test_login_failure_is_never_retryable(exception, monkeypatch):
    hub = AsyncMock()
    hub.login.side_effect = exception("synthetic login failure")
    sessions = _install_sessions(monkeypatch, hub)
    read = AsyncMock()
    monkeypatch.setattr(collection, "collect_owned_session", read)
    with pytest.raises(exception):
        await collection.collect("192.168.0.1", "fixture-pass", extended=False)
    assert len(sessions) == 1
    hub.logout.assert_not_awaited()
    read.assert_not_awaited()


@pytest.mark.parametrize(
    ("failure", "outcome"),
    [
        (SessionBusy, UpdateFailed),
        (SessionExpired, UpdateFailed),
        (AuthenticationError, ConfigEntryAuthFailed),
    ],
)
@pytest.mark.asyncio
async def test_ha_reauth_only_after_rejected_password(monkeypatch, failure, outcome):
    monkeypatch.setattr(coordinator, "collect", AsyncMock(side_effect=failure("synthetic failure")))
    fake = _coordinator()
    with pytest.raises(outcome):
        await coordinator.HubCoordinator._async_update_data(fake)


@pytest.mark.asyncio
async def test_wrong_device_poll_does_not_apply_telemetry(monkeypatch):
    device = js(
        swVersion="test-firmware", systemUptime="1 days 2h:3m:4s", cmMac="02:00:00:00:00:13"
    )
    sample = parse_snapshot(snapshot_inputs() | {"device": device})
    monkeypatch.setattr(coordinator, "collect", AsyncMock(return_value=sample))
    expected_id = hub_identity({"cmMac": "02:00:00:00:00:12"})
    fake = _coordinator(expected_id)
    with pytest.raises(UpdateFailed, match="does not identify the configured Hub"):
        await coordinator.HubCoordinator._async_update_data(fake)
    assert fake.boot_time is None


def _coordinator(identity="fixture-id"):
    hub = object.__new__(coordinator.HubCoordinator)
    hub._connection = {"host": "192.168.0.1", "password": "fixture"}
    hub._entry = SimpleNamespace(data=hub._connection, options={}, unique_id=identity)
    hub._session_lock = Lock()
    hub._closing = False
    hub.boot_time = None
    return hub


@pytest.mark.asyncio
async def test_connection_validation_joins_the_existing_entry_session(monkeypatch):
    hub = _coordinator()
    entry = hub._entry
    entry.setup_lock = Lock()
    entry.runtime_data = hub
    identify = AsyncMock(return_value=entry.unique_id)
    monkeypatch.setattr(config_flow, "_identify", identify)
    async with hub._session_lock:
        validation = create_task(config_flow._identify_for_entry("192.168.0.1", "fixture", entry))
        await sleep(0)
        assert not validation.done()
        identify.assert_not_awaited()
    assert await validation == entry.unique_id
    identify.assert_awaited_once_with("192.168.0.1", "fixture")


@pytest.mark.asyncio
async def test_stale_connection_is_not_admitted_after_credentials_change():
    hub = _coordinator()
    hub._entry.data = {"host": "192.168.0.1", "password": "replacement"}
    with pytest.raises(SessionBusy, match="being reloaded"):
        async with hub.async_session_scope():
            pytest.fail("The old owner admitted an operation with stale connection data")


@pytest.mark.parametrize(
    "extended,condition", [(False, "valid"), (True, "valid"), (True, "invalid"), (True, "empty")]
)
@pytest.mark.asyncio
async def test_extended_poll_gets_authoritative_mac_filter_rules(extended, condition):
    scripted = snapshot_inputs() | {"mac_filter": js(macFilterList=[])}

    async def fragment(group):
        if group in scripted:
            return scripted[group]
        return js(**dict.fromkeys(REQUIRED_MARKERS[group], "fixture"))

    hub = AsyncMock()
    hub.read_script.side_effect = fragment
    hub.read_clients.return_value = {"numHostEnt": 0}
    for reader in ("read_rules", "read_schedule", "read_dhcp", "read_wifi", "read_activity"):
        getattr(hub, reader).return_value = {}
    hub.read_mac_rules.return_value = {
        "valid": {"numberOfMACList": {"1": 1}, "0": ["Lab device", "02:00:00:00:00:01", "true"]},
        "empty": {"numberOfMACList": {"1": 0}},
        "invalid": {"numberOfMACList": {"1": 1}},
    }[condition]
    output = await collection.collect_owned_session(hub, extended=extended)
    assert output.online
    hub.write_mac_rules.assert_not_awaited()
    if not extended:
        hub.read_mac_rules.assert_not_awaited()
        assert "mac_filter_rules" not in output.groups
        return
    hub.read_mac_rules.assert_awaited_once()
    assert output.groups["mac_filter"]["macFilterList"] == []
    if condition == "invalid":
        assert output.errors["mac_filter_rules"] == "InvalidResponse"
        assert "mac_filter_rules" not in output.groups
    else:
        assert output.groups["mac_filter_rules"] == (
            [{"name": "Lab device", "mac": "02:00:00:00:00:01", "enabled": True}]
            if condition == "valid"
            else []
        )
