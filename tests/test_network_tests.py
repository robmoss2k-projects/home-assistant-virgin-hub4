"""Synthetic diagnostic session and cancellation tests; no network probes."""

from asyncio import Event
import json
from unittest.mock import AsyncMock

import pytest

from custom_components.virgin_hub4.client import CannotConnect, HubClient
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from custom_components.virgin_hub4.network_tests import _probe_parameters, run_probe, wizard
from test_client import DUAL_STACK, FakeHttp, LOGIN, MODE, fixture_hub
from test_parser import js

PING = {"status": "Complete", "SuccessCount": "4", "FailureCount": "0", "avgtime": "2.1"}
LINKS = {
    "LanPortStatus": ["Up", "Down", "Down", "Down"],
    "LanPortSpeed": ["1", "0", "0", "0"],
    "WiFiClientSignal": [-61, -60, -10],
}


@pytest.mark.parametrize("trace", [False, True])
def test_diagnostic_readback_has_the_global_default_and_an_explicit_override(trace):
    assert _probe_parameters({"target": "192.0.2.10"}, trace=trace)[1] == 120
    assert _probe_parameters({"target": "192.0.2.10", "timeout_seconds": 15}, trace=trace)[1] == 15


@pytest.mark.parametrize("trace", [False, True])
@pytest.mark.asyncio
async def test_probe_wire_request_and_verified_result(trace, monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.network_tests._wait", AsyncMock())
    key = "state" if trace else "status"
    finished = {key: "Complete", "result": ["synthetic hop"]} if trace else PING
    http = FakeHttp(
        MODE,
        LOGIN,
        DUAL_STACK,
        json.dumps({key: "None"}),
        '"OK"',
        json.dumps({key: "Requested"}),
        json.dumps(finished),
        "",
    )
    hub = HubClient(http, "192.168.0.1")
    await hub.login("synthetic")
    reply = await run_probe(hub, {"target": "192.0.2.10"}, trace=trace, cancel=Event())
    assert reply["status"] == "complete" and reply["target"] == "192.0.2.10"
    assert await hub.logout()
    path, read = http.requests[3]
    write_path, write = http.requests[4]
    if trace:
        assert path == "/php/ajaxGet_tool_trace.php"
        assert read["data"]["TraceRouteData[getting]"] == "status"
        assert write_path == "/php/ajaxSet_tool_trace.php"
        payload = json.loads(write["data"]["data"])
        assert payload.pop("csrf_nonce")
        assert payload == {
            "Host": "192.0.2.10",
            "MaxHops": "30",
            "Baseport": "33434",
            "DiagnosticsState": "Requested",
        }
        assert reply["result"]["lines"] == ["synthetic hop"]
    else:
        assert path == "/php/ajaxGet_ping_data.php"
        assert read["data"]["PingData[SuccessCount]"] == ""
        assert write_path == "/php/ajaxSet_ping_data.php"
        assert json.loads(write["data"]["PingData"]) == {
            "Host": "192.0.2.10",
            "NoofPings": "4",
            "PingSize": "64",
            "settings": "Requested",
        }
        assert reply["result"]["received"] == 4 and reply["result"]["average_ms"] == 2.1


@pytest.mark.asyncio
async def test_stale_same_result_is_unverified(monkeypatch):
    times = iter([0.0, 0.0, 1.0, 5.0])
    monkeypatch.setattr(
        "custom_components.virgin_hub4.network_tests.monotonic", lambda: next(times)
    )
    monkeypatch.setattr("custom_components.virgin_hub4.network_tests._wait", AsyncMock())
    hub = fixture_hub()
    hub.get_probe_status.return_value = PING
    outcome = await run_probe(
        hub, {"target": "192.0.2.1", "timeout_seconds": 5}, trace=False, cancel=Event()
    )
    assert outcome["status"] == "unverified"
    hub.set_probe.assert_awaited_once()


@pytest.mark.parametrize(
    ("trace", "incomplete"),
    [
        (False, {"status": "Complete", "SuccessCount": "0"}),
        (False, {"status": "Complete", "SuccessCount": "0", "FailureCount": "0"}),
        (True, {"state": "Complete", "result": [" ", ""]}),
    ],
)
async def test_terminal_flag_without_result_never_counts_as_completion(
    monkeypatch, trace, incomplete
):
    monotonic = iter([0.0, 0.0, 1.0, 5.0])
    monkeypatch.setattr(
        "custom_components.virgin_hub4.network_tests.monotonic", lambda: next(monotonic)
    )
    monkeypatch.setattr("custom_components.virgin_hub4.network_tests._wait", AsyncMock())
    hub = fixture_hub()
    hub.get_probe_status.side_effect = [
        {"state" if trace else "status": "None"},
        incomplete,
        incomplete,
    ]
    outcome = await run_probe(
        hub, {"target": "192.0.2.1", "timeout_seconds": 5}, trace=trace, cancel=Event()
    )
    assert outcome["status"] == "unverified" and outcome["hub_state"] == "Complete"
    hub.set_probe.assert_awaited_once()


@pytest.mark.asyncio
async def test_cancel_only_after_own_start_and_live_running_state(monkeypatch):
    cancel = Event()
    hub = fixture_hub()
    hub.get_probe_status.side_effect = [
        {"status": "None"},
        {"status": "Requested"},
        {"status": "Requested"},
        {"status": "Canceled"},
    ]
    monkeypatch.setattr(
        "custom_components.virgin_hub4.network_tests._wait",
        AsyncMock(side_effect=lambda *_: cancel.set()),
    )
    result = await run_probe(hub, {"target": "192.0.2.1"}, trace=False, cancel=cancel)
    assert result["status"] == "canceled"
    assert hub.set_probe.await_count == 2
    assert hub.set_probe.await_args.args[0] == {"settings": "Canceled"}
    hub.set_probe.reset_mock()
    cancel.clear()
    hub.get_probe_status.side_effect = [{"status": "Requested"}]
    assert (await run_probe(hub, {"target": "192.0.2.1"}, trace=False, cancel=cancel))[
        "status"
    ] == "busy"
    hub.set_probe.assert_not_awaited()


async def test_cancel_uses_the_full_readback_window_after_its_write(monkeypatch):
    cancel = Event()
    hub = fixture_hub()
    elapsed = 0.0

    def advance(*_):
        nonlocal elapsed
        if cancel.is_set():
            elapsed += 80.0
        else:
            elapsed += 70.0
            cancel.set()

    hub.get_probe_status.side_effect = [
        {"status": "None"},
        {"status": "Requested"},
        {"status": "Requested"},
        {"status": "Canceled"},
    ]
    monkeypatch.setattr("custom_components.virgin_hub4.network_tests.monotonic", lambda: elapsed)
    monkeypatch.setattr(
        "custom_components.virgin_hub4.network_tests._wait", AsyncMock(side_effect=advance)
    )
    result = await run_probe(hub, {"target": "192.0.2.1"}, trace=False, cancel=cancel)
    assert result["status"] == "canceled"
    assert elapsed == 150.0 and hub.set_probe.await_count == 2


@pytest.mark.parametrize(
    "target", ["http://example.com", "example.com extra", "255.255.255.255", "192.168.0.0/16"]
)
@pytest.mark.asyncio
async def test_target_must_be_one_host(target):
    hub = fixture_hub()
    with pytest.raises(InvalidSetting):
        await apply_owned_session(hub, "ping_test", {"target": target})
    hub.set_probe.assert_not_awaited()


@pytest.mark.asyncio
async def test_wizard_default_reads_links_but_does_not_cycle_them():
    hub = fixture_hub()
    hub.read_script.side_effect = [
        js(RouterMode="5"),
        js(
            cm_reg_value="0",
            cm_oper_value="0",
            cm_ip="0.0.0.0",
            wan_ip4="0.0.0.0",
            wan_ip6="::",
            fail_safe_mode="2",
            mta_admin_state="NOLINE",
            **{"24g_stat": "Up", "5g_stat": "Down"},
        ),
    ]
    hub.diagnostic_links.return_value = LINKS
    result = await wizard(hub, Event(), {})
    assert result["status"] == "complete"
    assert result["checks"]["broadband_ping"]["status"] == "not_run"
    assert result["checks"]["thermal_fail_safe"] is True
    assert result["checks"]["weak_wifi_clients"] == 1
    assert result["checks"]["ethernet_ports"][0]["link_up"] is True
    hub.exercise_ethernet_links.assert_not_awaited()
    hub.set_probe.assert_not_awaited()


async def test_wizard_reports_partial_when_the_hub_does_not_supply_link_results():
    hub = fixture_hub()
    hub.read_script.side_effect = [js(RouterMode="5"), js(cm_reg_value="0", cm_oper_value="0")]
    hub.diagnostic_links.side_effect = CannotConnect("fixture link status unavailable")
    result = await wizard(hub, Event(), {})
    assert result["status"] == "partial"
    assert result["checks"]["ethernet_ports"] is None
    assert result["checks"]["broadband_ping"]["status"] == "not_run"
    hub.exercise_ethernet_links.assert_not_awaited()


@pytest.mark.asyncio
async def test_wizard_confirmation_and_portal_dns_fallback(monkeypatch):
    monkeypatch.setattr("custom_components.virgin_hub4.network_tests._wait", AsyncMock())
    hub = fixture_hub()
    with pytest.raises(ValueError, match="explicit interruption"):
        await wizard(hub, Event(), {"exercise_ethernet": True})
    hub.read_script.side_effect = [
        js(RouterMode="5"),
        js(
            cm_reg_value="6",
            cm_oper_value="3",
            cm_ip="192.0.2.1",
            wan_ip4="192.0.2.2",
            wan_ip6="2001:db8::2",
            wan_ip_prov_mode="3",
        ),
    ]
    hub.diagnostic_links.return_value = LINKS
    hub.diagnostic_ipv6_dns.return_value = {"status": "0"}
    hub.get_probe_status.side_effect = [{"status": "None"}, PING]
    result = await wizard(
        hub, Event(), {"exercise_ethernet": True, "confirm_link_interruption": True}
    )
    assert result["checks"]["broadband_ping"]["target"] == "google.com"
    assert result["checks"]["ethernet_exercise"] == {
        "acknowledged_cycles": 3,
        "link_states_restored": True,
    }
    assert hub.exercise_ethernet_links.await_count == 3
