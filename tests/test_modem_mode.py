"""Both mode switch payloads, single-shot outcomes, and modem-mode reads."""

import json

import pytest

from custom_components.virgin_hub4.client import CannotConnect, HubClient, InvalidResponse
from custom_components.virgin_hub4.collection import collect_owned_session
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from custom_components.virgin_hub4.modem_mode import ModePlan, hub_identity
from test_client import DUAL_STACK, FakeHttp, LOGIN, MODE, fixture_hub
from test_parser import js, snapshot_inputs

DEVICE = {
    "swVersion": "fixture-version",
    "systemUptime": "0 days 0h:1m:0s",
    "cmMac": "02:00:00:00:00:12",
}
IDENTITY = hub_identity(DEVICE)


@pytest.mark.parametrize(
    ("before", "current", "target", "wire", "host"),
    [("5", "router", "modem", "1", "192.168.0.1"), ("1", "modem", "router", "0", "192.168.100.1")],
)
@pytest.mark.asyncio
async def test_mode_request_matches_portal_wire_contract(before, current, target, wire, host):
    http = FakeHttp(MODE, LOGIN, js(RouterMode=before), js(**DEVICE), DUAL_STACK, "", "")
    hub = HubClient(http, host)
    await hub.login("fixture-pass")
    result = await apply_owned_session(
        hub, "mode_submit", {"identity": IDENTITY, "current_mode": current, "target_mode": target}
    )
    assert result == {"status": "submission_uncertain", "verification_required": True}
    assert await hub.logout()
    path, request = http.requests[5]
    assert path == "/php/ajaxSet_modem_settings.php"
    payload = json.loads(request["data"]["data"])
    assert payload["csrf_nonce"] == request["headers"]["CSRF_NONCE"]
    assert payload["eRouterMode"] == wire


@pytest.mark.asyncio
async def test_no_write_for_different_hub_or_changed_mode():
    hub = fixture_hub()
    identity_of_other_hub = hub_identity(DEVICE | {"cmMac": "02:00:00:00:00:13"})
    hub.read_script.side_effect = [
        js(RouterMode="5"),
        js(**DEVICE),
        js(RouterMode="1"),
        js(**DEVICE),
    ]
    with pytest.raises(InvalidSetting, match="identity or operating mode changed"):
        await apply_owned_session(
            hub,
            "mode_submit",
            {"identity": identity_of_other_hub, "current_mode": "router", "target_mode": "modem"},
        )
    with pytest.raises(InvalidSetting, match="identity or operating mode changed"):
        await apply_owned_session(
            hub,
            "mode_submit",
            {"identity": IDENTITY, "current_mode": "router", "target_mode": "modem"},
        )
    hub.submit_operating_mode.assert_not_awaited()


@pytest.mark.asyncio
async def test_connection_loss_is_uncertain_and_modem_initialising_is_not_submitted():
    hub = fixture_hub()
    hub.read_script.side_effect = [js(RouterMode="5"), js(**DEVICE)] * 2
    hub.submit_operating_mode.side_effect = [
        CannotConnect("synthetic socket loss"),
        "Wait for modem init",
    ]
    data = {"identity": IDENTITY, "current_mode": "router", "target_mode": "modem"}
    assert (await apply_owned_session(hub, "mode_submit", data))["status"] == "submission_uncertain"
    assert (await apply_owned_session(hub, "mode_submit", data))["status"] == "not_submitted"
    assert hub.submit_operating_mode.await_count == 2  # One explicit request each.


def test_plan_hosts_confirmation_expiry_and_custom_router_address(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.modem_mode.monotonic", lambda: 100.0)
    observed = {"mode": "modem", "identity": IDENTITY}
    plan = ModePlan.create("192.168.100.1", observed, "router", "192.168.2.1")
    assert plan.public()["expected_management_address"] == "192.168.2.1"
    with pytest.raises(ValueError, match="local recovery"):
        plan.validate(plan.id, "192.168.100.1", False)
    with pytest.raises(ValueError, match="stale"):
        plan.validate(plan.id, "192.168.100.2", True)
    plan.validate(plan.id, "192.168.100.1", True)
    monkeypatch.setattr("custom_components.virgin_hub4.modem_mode.monotonic", lambda: 700.0)
    with pytest.raises(ValueError, match="stale"):
        plan.validate(plan.id, "192.168.100.1", True)


@pytest.mark.asyncio
async def test_modem_poll_retains_cable_diagnostics_if_router_home_is_absent():
    hub = fixture_hub()
    hub.read_script.side_effect = [
        js(RouterMode="1"),
        js(**DEVICE),
        snapshot_inputs()["line"],
        InvalidResponse("router-only home"),
    ]
    snapshot = await collect_owned_session(hub, extended=True)
    assert snapshot.online is True
    assert snapshot.groups["mode"]["RouterMode"] == "1"
    assert "radio" not in snapshot.groups
    assert snapshot.errors == {"home": "InvalidResponse"}
    assert [call.args[0] for call in hub.read_script.await_args_list] == [
        "mode",
        "device",
        "line",
        "home",
    ]
    hub.read_wifi.assert_not_awaited()
